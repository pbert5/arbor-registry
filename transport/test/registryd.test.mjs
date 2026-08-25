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
      },
      stdio: ['ignore', 'ignore', 'pipe'],
    })
    await waitForStatus(socketA)
    const firstStatus = await request(socketA, { operation: 'status' })
    const databaseAddresses = JSON.stringify(firstStatus.databaseAddresses)
    second = spawn(process.execPath, [daemon], {
      env: {
        ...base,
        ARBOR_REGISTRY_STATE_DIR: stateB,
        ARBOR_REGISTRY_SOCKET: socketB,
        ARBOR_REGISTRY_LISTEN: `/ip4/127.0.0.1/tcp/${portB}`,
        ARBOR_REGISTRY_DATABASE_ADDRESSES: databaseAddresses,
        ARBOR_REGISTRY_BOOTSTRAP_PEERS: `/ip4/127.0.0.1/tcp/${portA}/p2p/${firstStatus.peerId}`,
      },
      stdio: ['ignore', 'ignore', 'pipe'],
    })
    await waitForStatus(socketB)
    const event = { recordId: 'replicated-node', recordVersion: 1, payload: { source: 'peer-a' } }
    const appended = await request(socketA, { operation: 'append', stream: 'registry', event })
    assert.equal(appended.ok, true)

    let page
    for (let attempt = 0; attempt < 100; attempt++) {
      page = await request(socketB, { operation: 'list', stream: 'registry', cursor: 'v1:0', limit: 10 })
      if (page.ok && page.records.some(item => JSON.stringify(item.event) === JSON.stringify(event))) break
      await new Promise(resolve => setTimeout(resolve, 100))
    }
    assert.equal(page.ok, true)
    assert.deepEqual(page.records.map(item => item.event), [event])
  } finally {
    await stop(second)
    await stop(first)
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
    assert.deepEqual(results.map(result => result.cursor).sort(), ['v1:0', 'v1:1', 'v1:2'])
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
    assert.equal(appended.cursor, 'v1:0')
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
