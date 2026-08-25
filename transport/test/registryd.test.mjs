import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import fs from 'node:fs/promises'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

const daemon = path.join(import.meta.dirname, '..', 'registryd.mjs')

function request(socketPath, value) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath)
    let response = ''
    socket.on('connect', () => socket.end(`${JSON.stringify(value)}\n`))
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
  const env = { ...process.env, ARBOR_REGISTRY_STATE_DIR: root, ARBOR_REGISTRY_SOCKET: socketPath }
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
