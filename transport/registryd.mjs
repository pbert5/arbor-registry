import fs from 'node:fs/promises'
import net from 'node:net'
import path from 'node:path'
import process from 'node:process'
import { createHash } from 'node:crypto'
import { Helia } from '@helia/core'
import { bitswap } from '@helia/block-brokers'
import { createOrbitDB } from '@orbitdb/core'
import { createLibp2p } from 'libp2p'
import { gossipsub } from '@chainsafe/libp2p-gossipsub'
import { noise } from '@chainsafe/libp2p-noise'
import { yamux } from '@chainsafe/libp2p-yamux'
import { identify } from '@libp2p/identify'
import { createFromPrivKey } from '@libp2p/peer-id-factory'
import { generateKeyPair, marshalPrivateKey, unmarshalPrivateKey } from '@libp2p/crypto/keys'
import { tcp } from '@libp2p/tcp'
import { multiaddr } from '@multiformats/multiaddr'
import { LevelBlockstore } from 'blockstore-level'
import { LevelDatastore } from 'datastore-level'

const MAX_LINE = 1024 * 1024
const MAX_PAGE = 500
const SOCKET_MODE = 0o660
const canonical = value => JSON.stringify(value, (_, v) => v && typeof v === 'object' && !Array.isArray(v)
  ? Object.fromEntries(Object.keys(v).sort().map(k => [k, v[k]])) : v)
const digest = value => createHash('sha256').update(canonical(value)).digest('hex')
const reply = (ok, value = {}) => ok ? { ok: true, ...value } : { ok: false, error: value }

function validateIndex(index, streams) {
  if (!index || index.version !== 1 || !index.streams || typeof index.streams !== 'object' || Array.isArray(index.streams)) throw new Error('invalid transport index')
  for (const stream of streams) {
    const entries = index.streams[stream]
    if (!Array.isArray(entries) || entries.some(item => !item || typeof item.key !== 'string' || typeof item.hash !== 'string')) throw new Error('invalid transport index')
    if (new Set(entries.map(item => item.key)).size !== entries.length) throw new Error('invalid transport index')
  }
  return index
}

async function privateKeyAt(file) {
  try { return await unmarshalPrivateKey(await fs.readFile(file)) } catch (cause) {
    if (cause.code !== 'ENOENT') throw cause
    const key = await generateKeyPair('Ed25519')
    await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 })
    await fs.writeFile(file, marshalPrivateKey(key), { mode: 0o600, flag: 'wx' })
    return key
  }
}

// OrbitDB 4 expects the pre-1.x libp2p stream shape; this is the only
// compatibility adapter. It does not alter authentication or validation.
function orbitdbLibp2p(libp2p) {
  const stream = raw => {
    const queued = []; let waiting; let ended = false
    const source = { async next() { while (!queued.length && !ended) await new Promise(resolve => { waiting = resolve }); return queued.length ? { value: queued.shift(), done: false } : { done: true } }, [Symbol.asyncIterator]() { return this } }
    const sink = raw.sink(source)
    return { send(value) { if (ended) throw new Error('stream is closed'); queued.push(value); waiting?.(); waiting = undefined }, [Symbol.asyncIterator]: () => raw.source[Symbol.asyncIterator](), async close() { ended = true; waiting?.(); await sink; await raw.close() } }
  }
  return new Proxy(libp2p, { get(target, property) {
    if (property === 'handle') return (protocols, handler, options) => target.handle(protocols, event => handler(stream(event.stream), event.connection), options)
    if (property === 'dialProtocol') return async (...args) => stream(await target.dialProtocol(...args))
    const value = Reflect.get(target, property, target)
    return typeof value === 'function' ? value.bind(target) : value
  } })
}

export class TransportDaemon {
  constructor({ stateDir, streams = ['registry'], databaseAddresses = {}, listen = [], bootstrapPeers = [] }) {
    if (!stateDir) throw new Error('stateDir is required')
    this.stateDir = stateDir
    this.streams = [...new Set(streams)].filter(Boolean)
    if (!this.streams.length) throw new Error('at least one stream is required')
    this.addresses = { ...databaseAddresses }
    this.listen = listen
    if (!Array.isArray(bootstrapPeers)) throw new Error('bootstrapPeers must be an array')
    this.bootstrapPeers = bootstrapPeers.map(peer => {
      if (typeof peer !== 'string' || !peer) throw new Error('bootstrap peer must be a non-empty multiaddr')
      try { return multiaddr(peer) } catch { throw new Error('bootstrap peer must be a valid multiaddr') }
    })
    this.databases = new Map()
    this.index = { version: 1, streams: Object.fromEntries(this.streams.map(s => [s, []])) }
    this.appendQueue = Promise.resolve()
    this.indexQueue = Promise.resolve()
    this.lockPath = path.join(this.stateDir, 'transport-index.lock')
  }

  async start() {
    await fs.mkdir(this.stateDir, { recursive: true, mode: 0o700 })
    const indexFile = path.join(this.stateDir, 'transport-index.json')
    try { this.index = validateIndex(JSON.parse(await fs.readFile(indexFile, 'utf8')), this.streams) } catch (cause) { if (cause.code !== 'ENOENT') throw cause }
    this.privateKey = await privateKeyAt(path.join(this.stateDir, 'libp2p.key'))
    const peerId = await createFromPrivKey(this.privateKey)
    this.libp2p = await createLibp2p({ privateKey: this.privateKey, peerId, addresses: { listen: this.listen }, transports: [tcp()], connectionEncryption: [noise()], streamMuxers: [yamux()], services: { pubsub: gossipsub({ allowPublishToZeroPeers: true }), identify: identify() } })
    this.blockstore = new LevelBlockstore(path.join(this.stateDir, 'helia-blocks')); await this.blockstore.open()
    this.datastore = new LevelDatastore(path.join(this.stateDir, 'helia-data')); await this.datastore.open()
    this.helia = new Helia({ libp2p: this.libp2p, blockstore: this.blockstore, datastore: this.datastore, blockBrokers: [bitswap()] })
    await this.helia.start()
    await this.dialBootstrapPeers()
    const helia = this.helia
    const ipfs = { libp2p: orbitdbLibp2p(this.libp2p), pins: helia.pins, blockstore: { put: (cid, value, options) => helia.blockstore.put(cid, value, options), async *get(cid, options) { yield await helia.blockstore.get(cid, options) } } }
    this.orbitdb = await createOrbitDB({ ipfs, id: peerId.toString(), directory: path.join(this.stateDir, 'orbitdb') })
    for (const stream of this.streams) await this.open(stream)
    for (const stream of this.streams) await this.refreshIndex(stream)
  }

  async dialBootstrapPeers() {
    if (!this.bootstrapPeers.length) return true
    const results = await Promise.allSettled(this.bootstrapPeers.map(peer => this.libp2p.dial(peer)))
    return results.some(result => result.status === 'fulfilled')
  }

  async open(stream) {
    if (this.databases.has(stream)) return this.databases.get(stream)
    const database = await this.orbitdb.open(this.addresses[stream] ?? `arbor-registry-${stream}`, { type: 'events' })
    this.addresses[stream] = String(database.address); this.databases.set(stream, database)
    return database
  }

  async append(stream, event) {
    const operation = this.appendQueue.then(async () => {
      return this.withIndexLock(async () => {
        await this.reloadIndex()
        if (!this.streams.includes(stream) || !event || typeof event !== 'object' || Array.isArray(event)) throw new Error('invalid stream or event')
        await this.refreshIndex(stream)
        const key = digest(event); const entries = this.index.streams[stream] ??= []
        const existing = entries.find(item => item.key === key)
        if (existing) return { hash: existing.hash, duplicate: true }
        const hash = String(await (await this.open(stream)).add(event))
        entries.push({ key, hash }); await this.saveIndex()
        return { hash, duplicate: false }
      })
    })
    this.appendQueue = operation.catch(() => {})
    return operation
  }

  async list(stream, cursor = 'v1:0', limit = 100) {
    if (!this.streams.includes(stream) || !Number.isInteger(limit) || limit < 1 || limit > MAX_PAGE) throw new Error('invalid list request')
    await this.refreshIndex(stream)
    const entries = validateIndex(this.index, this.streams).streams[stream] ?? []
    let start
    const match = typeof cursor === 'string' && /^v1:(0|[1-9][0-9]*)$/.exec(cursor)
    if (match) start = Number(match[1])
    else if (typeof cursor === 'string') {
      const position = entries.findIndex(item => item.hash === cursor)
      if (position < 0) throw new Error('invalid cursor')
      start = position + 1
    } else throw new Error('invalid cursor')
    if (!Number.isSafeInteger(start) || start > Number.MAX_SAFE_INTEGER - limit) throw new Error('invalid cursor')
    const selected = entries.slice(start, start + limit); const db = await this.open(stream)
    const records = []
    for (const [sequence, item] of selected.entries()) records.push({ hash: item.hash, event: await db.get(item.hash), sequence: start + sequence })
    const nextCursor = `v1:${start + selected.length}`
    return { records, nextCursor, hasMore: start + selected.length < entries.length }
  }

  async saveIndex() {
    const write = this.indexQueue.then(async () => {
      const indexFile = path.join(this.stateDir, 'transport-index.json')
      const temporary = `${indexFile}.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}.tmp`
      await fs.writeFile(temporary, `${JSON.stringify(validateIndex(this.index, this.streams))}\n`, { mode: 0o600, flag: 'wx' })
      await fs.rename(temporary, indexFile)
    })
    this.indexQueue = write.catch(() => {})
    return write
  }

  async reloadIndex() {
    try { this.index = validateIndex(JSON.parse(await fs.readFile(path.join(this.stateDir, 'transport-index.json'), 'utf8')), this.streams) } catch (cause) {
      if (cause.code !== 'ENOENT') throw cause
    }
  }

  async withIndexLock(operation) {
    for (;;) {
      try {
        await fs.mkdir(this.lockPath)
        break
      } catch (cause) {
        if (cause.code !== 'EEXIST') throw cause
        await new Promise(resolve => setTimeout(resolve, 10))
      }
    }
    try { return await operation() } finally { await fs.rm(this.lockPath, { recursive: true, force: true }) }
  }

  async refreshIndex(stream) {
    const database = await this.open(stream)
    const entries = this.index.streams[stream] ??= []
    if (typeof database.iterator !== 'function') return
    const known = new Set(entries.map(item => item.hash))
    for await (const entry of database.iterator()) {
      const hash = String(entry.hash)
      if (!known.has(hash)) {
        entries.push({ key: digest(entry.value), hash })
        known.add(hash)
      }
    }
    await this.saveIndex()
  }
  async handle(request) {
    try {
      if (request.operation === 'health') return reply(true, { status: 'ok' })
      if (request.operation === 'status') return reply(true, { peerId: this.libp2p.peerId.toString(), databaseAddresses: this.addresses })
      if (request.operation === 'append') return reply(true, await this.append(request.stream, request.event))
      if (request.operation === 'list') return reply(true, await this.list(request.stream, request.cursor ?? 'v1:0', request.limit ?? 100))
      return reply(false, { code: 'unsupported_operation' })
    } catch (cause) { return reply(false, { code: 'invalid_request', message: cause.message }) }
  }

  async stop() { for (const db of this.databases.values()) await db.close(); await this.orbitdb?.stop(); await this.helia?.stop(); await this.datastore?.close(); await this.blockstore?.close(); await this.libp2p?.stop() }
}

export function startSocketServer(daemon, socketPath, authorization = {}) {
  const options = typeof authorization === 'string' ? { token: authorization } : authorization ?? {}
  const { token, authorizePeer, mode = SOCKET_MODE, uid, gid } = options
  if ((token == null || token === '') && typeof authorizePeer !== 'function') throw new Error('socket authorization is required')
  if (!Number.isInteger(mode) || mode < 0 || mode > 0o777 || (uid == null) !== (gid == null) || (uid != null && (!Number.isInteger(uid) || uid < 0 || !Number.isInteger(gid) || gid < 0))) throw new Error('invalid socket ownership or mode')
  const authorized = async request => (token != null && request != null && request.token === token)
    || typeof authorizePeer === 'function' && await authorizePeer(request)
  const server = net.createServer(socket => { let buffer = ''; socket.on('data', chunk => { buffer += chunk; if (buffer.length > MAX_LINE) return socket.destroy(); let end; while ((end = buffer.indexOf('\n')) >= 0) { const line = buffer.slice(0, end); buffer = buffer.slice(end + 1); let request; try { request = JSON.parse(line) } catch { socket.write(JSON.stringify(reply(false, { code: 'malformed_json' })) + '\n'); continue } Promise.resolve(authorized(request)).then(ok => ok ? daemon.handle(request) : reply(false, { code: 'authentication_failed' })).then(value => socket.write(JSON.stringify(value) + '\n')).catch(() => socket.destroy()) } }); socket.on('error', () => {}) })
  return fs.mkdir(path.dirname(socketPath), { recursive: true, mode: 0o750 }).then(async () => {
    try { if ((await fs.lstat(socketPath)).isSocket()) await fs.unlink(socketPath); else throw new Error('refusing to replace non-socket path') } catch (cause) { if (cause.code !== 'ENOENT') throw cause }
  }).then(() => new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(socketPath, async () => {
      try { await fs.chmod(socketPath, mode); if (uid != null) await fs.chown(socketPath, uid, gid); resolve(server) } catch (cause) { server.close(() => reject(cause)) }
    })
  }))
}

async function main() {
  const stateDir = process.env.ARBOR_REGISTRY_STATE_DIR ?? '/var/lib/arbor-registryd'
  const socketPath = process.env.ARBOR_REGISTRY_SOCKET ?? '/run/arbor-registryd/registry.sock'
  const streams = (process.env.ARBOR_REGISTRY_STREAMS ?? 'registry').split(',').filter(Boolean)
  const addresses = process.env.ARBOR_REGISTRY_DATABASE_ADDRESSES ? JSON.parse(process.env.ARBOR_REGISTRY_DATABASE_ADDRESSES) : {}
  const daemon = new TransportDaemon({ stateDir, streams, databaseAddresses: addresses, listen: (process.env.ARBOR_REGISTRY_LISTEN ?? '').split(',').filter(Boolean), bootstrapPeers: (process.env.ARBOR_REGISTRY_BOOTSTRAP_PEERS ?? '').split(',').filter(Boolean) })
  const token = process.env.ARBOR_REGISTRY_SOCKET_TOKEN
  if (!token) throw new Error('ARBOR_REGISTRY_SOCKET_TOKEN is required')
  await daemon.start()
  const server = await startSocketServer(daemon, socketPath, { token })
  const stop = async () => { await new Promise(resolve => server.close(resolve)); await daemon.stop(); await fs.unlink(socketPath).catch(() => {}); process.exit(0) }
  process.once('SIGTERM', stop); process.once('SIGINT', stop)
}
if (process.argv[1] === new URL(import.meta.url).pathname) main().catch(cause => { console.error(cause); process.exit(1) })
