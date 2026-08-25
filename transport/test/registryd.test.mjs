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
    socket.on('close', () => resolve(JSON.parse(response)))
  })
}

async function waitForSocket(socketPath) {
  for (let attempt = 0; attempt < 100; attempt++) {
    try { await fs.access(socketPath); return } catch { await new Promise(resolve => setTimeout(resolve, 20)) }
  }
  throw new Error('daemon socket did not appear')
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
