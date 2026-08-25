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
import { LevelBlockstore } from 'blockstore-level'
import { LevelDatastore } from 'datastore-level'

const MAX_LINE = 1024 * 1024
const MAX_PAGE = 500
const canonical = value => JSON.stringify(value, (_, v) => v && typeof v === 'object' && !Array.isArray(v)
  ? Object.fromEntries(Object.keys(v).sort().map(k => [k, v[k]])) : v)
const digest = value => createHash('sha256').update(canonical(value)).digest('hex')
const reply = (ok, value = {}) => ok ? { ok: true, ...value } : { ok: false, error: value }

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
    this.bootstrapPeers = bootstrapPeers
    this.databases = new Map()
    this.index = { version: 1, streams: Object.fromEntries(this.streams.map(s => [s, []])) }
  }

  async start() {
    await fs.mkdir(this.stateDir, { recursive: true, mode: 0o700 })
    const indexFile = path.join(this.stateDir, 'transport-index.json')
    try { this.index = JSON.parse(await fs.readFile(indexFile, 'utf8')) } catch (cause) { if (cause.code !== 'ENOENT') throw cause }
    this.privateKey = await privateKeyAt(path.join(this.stateDir, 'libp2p.key'))
    const peerId = await createFromPrivKey(this.privateKey)
    this.libp2p = await createLibp2p({ privateKey: this.privateKey, peerId, addresses: { listen: this.listen }, transports: [tcp()], connectionEncryption: [noise()], streamMuxers: [yamux()], services: { pubsub: gossipsub({ allowPublishToZeroPeers: true }), identify: identify() } })
    this.blockstore = new LevelBlockstore(path.join(this.stateDir, 'helia-blocks')); await this.blockstore.open()
    this.datastore = new LevelDatastore(path.join(this.stateDir, 'helia-data')); await this.datastore.open()
    this.helia = new Helia({ libp2p: this.libp2p, blockstore: this.blockstore, datastore: this.datastore, blockBrokers: [bitswap()] })
    await this.helia.start()
    const helia = this.helia
    const ipfs = { libp2p: orbitdbLibp2p(this.libp2p), pins: helia.pins, blockstore: { put: (cid, value, options) => helia.blockstore.put(cid, value, options), async *get(cid, options) { yield await helia.blockstore.get(cid, options) } } }
    this.orbitdb = await createOrbitDB({ ipfs, id: peerId.toString(), directory: path.join(this.stateDir, 'orbitdb') })
    for (const stream of this.streams) await this.open(stream)
  }

  async open(stream) {
    if (this.databases.has(stream)) return this.databases.get(stream)
    const database = await this.orbitdb.open(this.addresses[stream] ?? `arbor-registry-${stream}`, { type: 'events' })
    this.addresses[stream] = String(database.address); this.databases.set(stream, database)
    return database
  }

  async append(stream, event) {
    if (!this.streams.includes(stream) || !event || typeof event !== 'object' || Array.isArray(event)) throw new Error('invalid stream or event')
    const key = digest(event); const entries = this.index.streams[stream] ??= []
    const existing = entries.find(item => item.key === key)
    if (existing) return { hash: existing.hash, duplicate: true }
    const hash = String(await (await this.open(stream)).add(event))
    entries.push({ key, hash }); await this.saveIndex()
    return { hash, duplicate: false }
  }

  async list(stream, cursor = 'v1:0', limit = 100) {
    if (!this.streams.includes(stream) || !Number.isInteger(limit) || limit < 1 || limit > MAX_PAGE) throw new Error('invalid list request')
    const entries = this.index.streams[stream] ?? []; const match = /^v1:(0|[1-9][0-9]*)$/.exec(cursor)
    if (!match) throw new Error('invalid cursor')
    const start = Number(match[1]); const selected = entries.slice(start, start + limit); const db = await this.open(stream)
    const records = []
    for (const [sequence, item] of selected.entries()) records.push({ hash: item.hash, event: await db.get(item.hash), sequence: start + sequence })
    const nextCursor = `v1:${start + selected.length}`
    return { records, nextCursor, hasMore: start + selected.length < entries.length }
  }

  async saveIndex() { await fs.writeFile(path.join(this.stateDir, 'transport-index.json'), `${JSON.stringify(this.index)}\n`, { mode: 0o600 }) }
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

export function startSocketServer(daemon, socketPath, token = null) {
  const server = net.createServer(socket => { let buffer = ''; socket.on('data', chunk => { buffer += chunk; if (buffer.length > MAX_LINE) return socket.destroy(); let end; while ((end = buffer.indexOf('\n')) >= 0) { const line = buffer.slice(0, end); buffer = buffer.slice(end + 1); let request; try { request = JSON.parse(line) } catch { socket.write(JSON.stringify(reply(false, { code: 'malformed_json' })) + '\n'); continue } Promise.resolve(token != null && request.token !== token ? reply(false, { code: 'authentication_failed' }) : daemon.handle(request)).then(value => socket.write(JSON.stringify(value) + '\n')) } }); socket.on('error', () => {}) })
  return fs.mkdir(path.dirname(socketPath), { recursive: true, mode: 0o750 }).then(() => fs.unlink(socketPath).catch(cause => { if (cause.code !== 'ENOENT') throw cause })).then(() => new Promise((resolve, reject) => { server.once('error', reject); server.listen(socketPath, () => resolve(server)) }))
}

async function main() {
  const stateDir = process.env.ARBOR_REGISTRY_STATE_DIR ?? '/var/lib/arbor-registryd'
  const socketPath = process.env.ARBOR_REGISTRY_SOCKET ?? '/run/arbor-registryd/registry.sock'
  const streams = (process.env.ARBOR_REGISTRY_STREAMS ?? 'registry').split(',').filter(Boolean)
  const addresses = process.env.ARBOR_REGISTRY_DATABASE_ADDRESSES ? JSON.parse(process.env.ARBOR_REGISTRY_DATABASE_ADDRESSES) : {}
  const daemon = new TransportDaemon({ stateDir, streams, databaseAddresses: addresses, listen: (process.env.ARBOR_REGISTRY_LISTEN ?? '').split(',').filter(Boolean) })
  await daemon.start(); const server = await startSocketServer(daemon, socketPath, process.env.ARBOR_REGISTRY_SOCKET_TOKEN || null)
  const stop = async () => { await new Promise(resolve => server.close(resolve)); await daemon.stop(); await fs.unlink(socketPath).catch(() => {}); process.exit(0) }
  process.once('SIGTERM', stop); process.once('SIGINT', stop)
}
if (process.argv[1] === new URL(import.meta.url).pathname) main().catch(cause => { console.error(cause); process.exit(1) })
