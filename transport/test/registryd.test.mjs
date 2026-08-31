import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import fs from 'node:fs/promises'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { startSocketServer, TransportDaemon } from '../registryd.mjs'

const daemon = path.join(import.meta.dirname, '..', 'registryd.mjs')

function request(socketPath, value, token = 'test-token') {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath)
    let response = ''
    socket.on('connect', () => socket.end(`${JSON.stringify({ ...value, token })}\n`))
    socket.on('data', chunk => { response += chunk })
    socket.on('error', reject)
    socket.on('close', () => {
      try { resolve(JSON.parse(response)) } catch (error) { reject(error) }
    })
  })
}

async function waitForSocket(socketPath) {
  for (let attempt = 0; attempt < 100; attempt++) {
    try { await fs.access(socketPath); return } catch { await new Promise(resolve => setTimeout(resolve, 20)) }
  }
  throw new Error('daemon socket did not appear')
}

async function freeTcpPort() {
  const probe = net.createServer()
  await new Promise((resolve, reject) => {
    probe.once('error', reject)
    probe.listen(0, '127.0.0.1', resolve)
  })
  const port = probe.address().port
  await new Promise(resolve => probe.close(resolve))
  return port
}

async function waitForStatus(socketPath) {
  for (let attempt = 0; attempt < 200; attempt++) {
    try {
      const result = await request(socketPath, { operation: 'status' })
      if (result.ok && result.peerId && result.databaseAddresses) return result
    } catch {}
    await new Promise(resolve => setTimeout(resolve, 50))
  }
  throw new Error(`daemon status did not become available: ${socketPath}`)
}

async function waitForRecords(socketPath, ids) {
  let page
  for (let attempt = 0; attempt < 120; attempt++) {
    page = await request(socketPath, { operation: 'list', stream: 'registry', cursor: 'v1:0', limit: 20 })
    const records = page.ok ? page.records.map(item => item.event) : []
    if (ids.every(id => records.some(event => event.recordId === id))) return records
    await new Promise(resolve => setTimeout(resolve, 100))
  }
  throw new Error(`records did not arrive at ${socketPath}: ${ids.join(', ')}`)
}

test('separate daemon processes preserve the typed append/list transport', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'arbor-registryd-'))
  const socketPath = path.join(root, 'registry.sock')
  const env = { ...process.env, ARBOR_REGISTRY_STATE_DIR: root, ARBOR_REGISTRY_SOCKET: socketPath, ARBOR_REGISTRY_SOCKET_TOKEN: 'test-token' }
  const start = () => spawn(process.execPath, [daemon], { env, stdio: ['ignore', 'ignore', 'pipe'] })
  let child = start()
  try {
    await waitForSocket(socketPath)
    const event = { recordId: 'node-a', recordVersion: 1, payload: { role: 'member' } }
    const appended = await request(socketPath, { operation: 'append', stream: 'registry', event })
    assert.equal(appended.ok, true)
    assert.equal((await request(socketPath, { operation: 'append', stream: 'registry', event })).duplicate, true)
    child.kill('SIGTERM'); await new Promise(resolve => child.once('exit', resolve))
    child = start(); await waitForSocket(socketPath)
    const page = await request(socketPath, { operation: 'list', stream: 'registry', cursor: 'v1:0', limit: 10 })
    assert.deepEqual(page.records.map(item => item.event), [event])
  } finally {
    if (!child.killed) child.kill('SIGTERM')
    await fs.rm(root, { recursive: true, force: true })
  }
})

test('legacy name-only opens bind the manifest to each creator identity', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'arbor-registryd-manifest-'))
  const first = new TransportDaemon({ stateDir: path.join(root, 'a') })
  const second = new TransportDaemon({ stateDir: path.join(root, 'b') })
  try {
    await first.start(); await second.start()
    assert.notEqual(first.addresses.registry, second.addresses.registry)
    assert.notDeepEqual(first.databases.get('registry').access.write, ['*'])
    assert.notDeepEqual(second.databases.get('registry').access.write, ['*'])
    assert.notEqual(first.databases.get('registry').access.address, second.databases.get('registry').access.address)
  } finally {
    await second.stop(); await first.stop()
    await fs.rm(root, { recursive: true, force: true })
  }
})

test('independent realm-scoped opens share an address and raw writers are not creator-bound', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'arbor-registryd-realm-'))
  const first = new TransportDaemon({ stateDir: path.join(root, 'a'), realmId: 'acceptance-realm', protocolEpoch: 1 })
  const second = new TransportDaemon({ stateDir: path.join(root, 'b'), realmId: 'acceptance-realm', protocolEpoch: 1 })
  try {
    await first.start(); await second.start()
    assert.equal(first.addresses.registry, second.addresses.registry)
    assert.deepEqual(first.databases.get('registry').access.write, ['*'])
    assert.deepEqual(second.databases.get('registry').access.write, ['*'])
    assert.equal((await first.append('registry', { recordId: 'realm-a', recordVersion: 1 })).duplicate, false)
    assert.equal((await second.append('registry', { recordId: 'realm-b', recordVersion: 1 })).duplicate, false)
    assert.equal(JSON.parse(await fs.readFile(path.join(root, 'b', 'transport-bootstrap.json'), 'utf8')).databaseAddresses.registry, second.addresses.registry)
  } finally {
    await second.stop(); await first.stop()
    await fs.rm(root, { recursive: true, force: true })
  }
})

test('realm bootstrap persists and conflicting configuration fails closed', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'arbor-registryd-realm-persist-'))
  const first = new TransportDaemon({ stateDir: root, realmId: 'persisted-realm', protocolEpoch: 1 })
  await first.start(); const address = first.addresses.registry; await first.stop()
  const restarted = new TransportDaemon({ stateDir: root, realmId: 'persisted-realm', protocolEpoch: 1 })
  await restarted.start()
  assert.equal(restarted.addresses.registry, address)
  await restarted.stop()
  await assert.rejects(() => new TransportDaemon({ stateDir: root, realmId: 'different-realm', protocolEpoch: 1 }).start(), /conflicts with configured realm/)
  await fs.rm(root, { recursive: true, force: true })
})

test('two daemons replicate an OrbitDB event over a bootstrapped libp2p peer', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'arbor-registryd-peers-'))
  const portA = await freeTcpPort()
  const portB = await freeTcpPort()
  const stateA = path.join(root, 'a')
  const stateB = path.join(root, 'b')
  const socketA = path.join(root, 'a.sock')
  const socketB = path.join(root, 'b.sock')
  const base = { ...process.env, ARBOR_REGISTRY_SOCKET_TOKEN: 'test-token' }
  let first
  let second
  const stop = async child => {
    if (!child || child.killed) return
    child.kill('SIGTERM')
    await new Promise(resolve => child.once('exit', resolve))
  }
  try {
    first = spawn(process.execPath, [daemon], {
      env: {
        ...base,
        ARBOR_REGISTRY_STATE_DIR: stateA,
        ARBOR_REGISTRY_SOCKET: socketA,
        ARBOR_REGISTRY_LISTEN: `/ip4/127.0.0.1/tcp/${portA}`,
        ARBOR_REGISTRY_REALM_ID: 'transport-test-realm',
      },
      stdio: ['ignore', 'ignore', 'pipe'],
    })
    await waitForStatus(socketA)
    const firstStatus = await request(socketA, { operation: 'status' })
    second = spawn(process.execPath, [daemon], {
      env: {
        ...base,
        ARBOR_REGISTRY_STATE_DIR: stateB,
        ARBOR_REGISTRY_SOCKET: socketB,
        ARBOR_REGISTRY_LISTEN: `/ip4/127.0.0.1/tcp/${portB}`,
        ARBOR_REGISTRY_REALM_ID: 'transport-test-realm',
        ARBOR_REGISTRY_BOOTSTRAP_PEERS: `/ip4/127.0.0.1/tcp/${portA}/p2p/${firstStatus.peerId}`,
      },
      stdio: ['ignore', 'ignore', 'pipe'],
    })
    await waitForStatus(socketB)
    const event = { recordId: 'replicated-node', recordVersion: 1, payload: { source: 'peer-a' } }
    const secondEvent = { recordId: 'replicated-node-b', recordVersion: 1, payload: { source: 'peer-b' } }
    assert.equal((await request(socketA, { operation: 'append', stream: 'registry', event })).ok, true)

    let page
    for (let attempt = 0; attempt < 100; attempt++) {
      page = await request(socketB, { operation: 'list', stream: 'registry', cursor: 'v1:0', limit: 10 })
      if (page.ok && page.records.some(item => item.event.recordId === event.recordId)) break
      await new Promise(resolve => setTimeout(resolve, 100))
    }
    assert.equal(page.ok, true)
    assert.equal(page.records.some(item => item.event.recordId === event.recordId), true, JSON.stringify({ page, a: await request(socketA, { operation: 'status' }), b: await request(socketB, { operation: 'status' }) }))
    assert.equal((await request(socketB, { operation: 'append', stream: 'registry', event: secondEvent })).ok, true)
    const firstPage = await waitForRecords(socketA, ['replicated-node-b'])
    assert.equal(firstPage.some(item => item.recordId === 'replicated-node'), true)
  } finally {
    await stop(second)
    await stop(first)
    await fs.rm(root, { recursive: true, force: true })
  }
})

test('three persisted daemons replay missed events after restart and reconnect', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'arbor-registryd-recovery-'))
  const ports = await Promise.all([freeTcpPort(), freeTcpPort(), freeTcpPort()])
  const states = ports.map((_, index) => path.join(root, String.fromCharCode(97 + index)))
  const sockets = ports.map((_, index) => path.join(root, `${String.fromCharCode(97 + index)}.sock`))
  const base = { ...process.env, ARBOR_REGISTRY_SOCKET_TOKEN: 'test-token' }
  const children = []
  const start = async index => {
    const bootstrap = index === 0 ? [] : [`/ip4/127.0.0.1/tcp/${ports[0]}/p2p/${(await request(sockets[0], { operation: 'status' })).peerId}`]
    const child = spawn(process.execPath, [daemon], {
      env: {
        ...base,
        ARBOR_REGISTRY_STATE_DIR: states[index],
        ARBOR_REGISTRY_SOCKET: sockets[index],
        ARBOR_REGISTRY_LISTEN: `/ip4/127.0.0.1/tcp/${ports[index]}`,
        ...(index === 0 ? {} : {
          ARBOR_REGISTRY_DATABASE_ADDRESSES: JSON.stringify((await request(sockets[0], { operation: 'status' })).databaseAddresses),
          ARBOR_REGISTRY_BOOTSTRAP_PEERS: bootstrap.join(','),
        }),
      },
      stdio: ['ignore', 'ignore', 'pipe'],
    })
    children[index] = child
    await waitForStatus(sockets[index])
    return request(sockets[index], { operation: 'status' })
  }
  const stop = async index => {
    const child = children[index]
    if (!child || child.exitCode !== null) return
    child.kill('SIGTERM')
    await new Promise(resolve => child.once('exit', resolve))
  }
  try {
    const firstStatus = await start(0)
    const secondStatus = await start(1)
    const thirdStatus = await start(2)
    assert.equal(new Set([firstStatus.peerId, secondStatus.peerId, thirdStatus.peerId]).size, 3)
    const initial = { recordId: 'initial', recordVersion: 1, payload: { phase: 'connected' } }
    const duringPartition = { recordId: 'during-partition', recordVersion: 1, payload: { phase: 'replay' } }
    const afterReconnect = { recordId: 'after-reconnect', recordVersion: 1, payload: { phase: 'recovered' } }
    assert.equal((await request(sockets[0], { operation: 'append', stream: 'registry', event: initial })).ok, true)
    await waitForRecords(sockets[1], ['initial']); await waitForRecords(sockets[2], ['initial'])

    const peerIdBeforeRestart = (await request(sockets[1], { operation: 'status' })).peerId
    await stop(1)
    assert.equal((await request(sockets[0], { operation: 'append', stream: 'registry', event: duringPartition })).ok, true)
    const livePeerRecords = await waitForRecords(sockets[2], ['initial', 'during-partition'])
    assert.equal(livePeerRecords.filter(event => event.recordId === 'during-partition').length, 1)

    const restarted = await start(1)
    assert.equal(restarted.peerId, peerIdBeforeRestart, 'recovery should retain the peer identity')
    const replayed = await waitForRecords(sockets[1], ['initial', 'during-partition'])
    assert.equal(replayed.filter(event => event.recordId === 'during-partition').length, 1)
    assert.equal((await request(sockets[0], { operation: 'append', stream: 'registry', event: afterReconnect })).ok, true)
    await waitForRecords(sockets[1], ['after-reconnect']); await waitForRecords(sockets[2], ['after-reconnect'])
    assert.equal((await request(sockets[0], { operation: 'append', stream: 'registry', event: duringPartition })).duplicate, true)
    assert.ok(firstStatus.peerId)
  } finally {
    await stop(2); await stop(1); await stop(0)
    await fs.rm(root, { recursive: true, force: true })
  }
})

test('socket authorization fails closed and protects existing non-socket paths', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'arbor-registryd-'))
  const socketPath = path.join(root, 'registry.sock')
  const daemon = { handle: async () => ({ ok: true }) }
  await assert.rejects(() => startSocketServer(daemon, socketPath), /authorization is required/)
  await fs.writeFile(socketPath, 'keep me')
  await assert.rejects(() => startSocketServer(daemon, socketPath, { token: 'secret' }), /non-socket path/)
  assert.equal(await fs.readFile(socketPath, 'utf8'), 'keep me')
  await fs.rm(root, { recursive: true, force: true })
})

test('socket authorization, mode, and peer authorization are explicit', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'arbor-registryd-'))
  const tokenSocket = path.join(root, 'token.sock')
  const tokenServer = await startSocketServer({ handle: async request => ({ ok: true, operation: request.operation }) }, tokenSocket, { token: 'secret' })
  try {
    assert.equal((await fs.stat(tokenSocket)).mode & 0o777, 0o660)
    assert.equal((await request(tokenSocket, { operation: 'health' }, 'wrong')).ok, false)
    assert.deepEqual(await request(tokenSocket, { operation: 'health' }, 'secret'), { ok: true, operation: 'health' })
  } finally { await new Promise(resolve => tokenServer.close(resolve)) }

  const peerSocket = path.join(root, 'peer.sock')
  const peerServer = await startSocketServer({ handle: async () => ({ ok: true }) }, peerSocket, { authorizePeer: async request => request.peer === 'trusted' })
  try {
    assert.equal((await request(peerSocket, { operation: 'health', peer: 'untrusted' })).ok, false)
    assert.equal((await request(peerSocket, { operation: 'health', peer: 'trusted' })).ok, true)
  } finally { await new Promise(resolve => peerServer.close(resolve)) }
  await fs.rm(root, { recursive: true, force: true })
})

test('concurrent appends retain one ordered cursor per event', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'arbor-registryd-'))
  const daemon = new TransportDaemon({ stateDir: root })
  const events = new Map()
  daemon.open = async () => ({
    add: async event => { const hash = `hash-${events.size}`; events.set(hash, event); return hash },
    get: async hash => events.get(hash)
  })
  try {
    const values = [{ id: 1 }, { id: 2 }, { id: 3 }]
    const results = await Promise.all(values.map(event => daemon.append('registry', event)))
    assert.equal(new Set(results.map(result => result.hash)).size, 3)
    assert.deepEqual(results.map(result => result.cursor).sort(), ['v2:hash-0', 'v2:hash-1', 'v2:hash-2'])
    assert.deepEqual((await daemon.list('registry', 'v1:0', 10)).records.map(record => record.sequence), [0, 1, 2])
  } finally { await fs.rm(root, { recursive: true, force: true }) }
})

test('append cursor is inclusive and stale lock leases are recovered', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'arbor-registryd-'))
  const daemon = new TransportDaemon({ stateDir: root })
  const events = new Map()
  daemon.open = async () => ({
    add: async event => { const hash = `hash-${events.size}`; events.set(hash, event); return hash },
    get: async hash => events.get(hash)
  })
  await fs.mkdir(path.join(root, 'transport-index.lock'), { recursive: true })
  await fs.writeFile(path.join(root, 'transport-index.lock', 'owner.json'), JSON.stringify({ owner: 'dead-host', pid: 999999, acquiredAt: 0 }))
  try {
    const appended = await daemon.append('registry', { id: 1 })
    assert.equal(appended.cursor, 'v2:hash-0')
    assert.deepEqual((await daemon.list('registry', appended.cursor, 10)).records.map(record => record.event), [{ id: 1 }])
  } finally { await fs.rm(root, { recursive: true, force: true }) }
})

test('an old owner release cannot remove a successor lock after takeover', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'arbor-registryd-'))
  const first = new TransportDaemon({ stateDir: root })
  const second = new TransportDaemon({ stateDir: root })
  let releaseFirst
  let releaseSecond
  let enteredSecond
  const firstHeld = new Promise(resolve => { releaseFirst = resolve })
  const secondHeld = new Promise(resolve => { releaseSecond = resolve })
  const secondEntered = new Promise(resolve => { enteredSecond = resolve })
  const firstLock = first.withIndexLock(async () => {
    const owner = (await fs.readdir(first.lockPath)).find(file => file.startsWith('owner-'))
    await fs.writeFile(path.join(first.lockPath, owner), JSON.stringify({ token: owner.slice(6, -5), owner: 'dead-host', pid: 999999, acquiredAt: 0, leaseAt: 0 }))
    await firstHeld
  })
  try {
    const secondLock = second.withIndexLock(async () => { enteredSecond(); await secondHeld })
    await new Promise(resolve => setTimeout(resolve, 20))
    releaseFirst()
    await secondEntered
    const successor = (await fs.readdir(root + '/transport-index.lock')).find(file => file.startsWith('owner-'))
    assert.ok(successor, 'successor lock should remain while its owner is active')
    releaseSecond()
    await Promise.all([firstLock, secondLock])
  } finally {
    releaseFirst(); releaseSecond()
    await fs.rm(root, { recursive: true, force: true })
  }
})

test('malformed replicated entries are quarantined and skipped', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'arbor-registryd-'))
  const daemon = new TransportDaemon({ stateDir: root })
  daemon.open = async () => ({
    iterator: async function * () { yield { hash: 42, value: {} }; yield { hash: 'good', value: { id: 1 } } },
    get: async hash => ({ id: hash })
  })
  try {
    await daemon.withIndexLock(async () => { await daemon.refreshIndex('registry') })
    assert.deepEqual(daemon.index.streams.registry.map(item => item.hash), ['good'])
    assert.match(await fs.readFile(path.join(root, 'transport-quarantine.jsonl'), 'utf8'), /malformed-replicated-entry/)
  } finally { await fs.rm(root, { recursive: true, force: true }) }
})

test('v2-after preserves a late earlier-clock event across restart', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'arbor-registryd-late-cursor-'))
  const entries = [{ hash: 'hash-a', value: { id: 'a' }, clock: { time: 20, id: 'a' } }]
  const open = async () => ({ iterator: async function * () { yield * entries }, get: async hash => entries.find(entry => entry.hash === hash).value })
  const first = new TransportDaemon({ stateDir: root }); first.open = open
  try {
    await first.withIndexLock(async () => { await first.refreshIndex('registry'); await first.saveIndex() })
    const saved = await first.list('registry', 'v2:begin', 10)
    entries.push({ hash: 'hash-b', value: { id: 'b' }, clock: { time: 10, id: 'b' } })
    assert.deepEqual((await first.list('registry', saved.nextCursor, 10)).records.map(item => item.hash), ['hash-b'])
    assert.deepEqual(first.index.streams.registry.map(item => item.hash), ['hash-b', 'hash-a'])

    const restarted = new TransportDaemon({ stateDir: root }); restarted.open = open
    assert.deepEqual((await restarted.list('registry', saved.nextCursor, 10)).records.map(item => item.hash), ['hash-b'])
  } finally { await fs.rm(root, { recursive: true, force: true }) }
})

test('healing observation subsets converges deterministic order and duplicate winner', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'arbor-registryd-healing-'))
  const entries = [
    { hash: 'late', value: { id: 'late' }, clock: { time: 2, id: 'b' } },
    { hash: 'loser', value: { id: 'same' }, clock: { time: 4, id: 'z' } },
    { hash: 'early', value: { id: 'early' }, clock: { time: 1, id: 'a' } },
    { hash: 'winner', value: { id: 'same' }, clock: { time: 3, id: 'a' } },
  ]
  const makeDaemon = (stateDir, observed) => {
    const daemon = new TransportDaemon({ stateDir })
    daemon.open = async () => ({ iterator: async function * () { yield * observed }, get: async hash => entries.find(entry => entry.hash === hash)?.value })
    return daemon
  }
  const first = makeDaemon(path.join(root, 'first'), entries)
  const second = makeDaemon(path.join(root, 'second'), [...entries].reverse())
  try {
    await fs.mkdir(path.join(root, 'first'), { recursive: true }); await fs.mkdir(path.join(root, 'second'), { recursive: true })
    first.index.streams.registry = [{ key: 'late', hash: 'late', order: '1:late' }]
    second.index.streams.registry = [{ key: 'early', hash: 'early', order: '1:early' }]
    await first.refreshIndex('registry'); await second.refreshIndex('registry')
    assert.deepEqual(first.index.streams.registry.map(item => item.hash), ['early', 'late', 'winner'])
    assert.deepEqual(second.index.streams.registry.map(item => item.hash), first.index.streams.registry.map(item => item.hash))
    assert.equal(first.index.streams.registry.some(item => item.hash === 'loser'), false)
    await assert.rejects(() => first.list('registry', 'v2-after:loser', 10), /invalid cursor/)
  } finally { await fs.rm(root, { recursive: true, force: true }) }
})
