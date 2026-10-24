// SPDX-License-Identifier: AGPL-3.0-only
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
const source = readFileSync(resolve(import.meta.dirname, '../../../../agents/roomler-desktop/src/front/account.js'), 'utf8')
const invoke = vi.fn()
function start() { document.body.innerHTML = '<button id="account-devices">Devices</button><button id="account-received">Received</button><button id="account-sent">Sent</button><p id="account-error" hidden></p>'; new Function('window', source)({ Roomler: { $: (id: string) => document.getElementById(id), invoke } }) }
beforeEach(() => { invoke.mockReset(); invoke.mockResolvedValue(undefined); start() })
async function click(id: string) { document.getElementById(id)!.click(); await new Promise(resolve => setTimeout(resolve, 0)) }
describe('desktop personal account entry uses whitelisted native IPC without credentials', () => {
  it.each([['account-devices', 'devices'], ['account-received', 'received'], ['account-sent', 'sent']])('opens %s through the account window', async (id, section) => { await click(id); expect(invoke).toHaveBeenCalledWith('cmd_open_account', { section }); expect(invoke.mock.calls[0][1]).not.toHaveProperty('token') })
  it('does not expose native error details or silently open a browser when the account window fails', async () => { invoke.mockRejectedValue(new Error('SECRET_DIAGNOSTIC')); await click('account-devices'); expect(document.getElementById('account-error')!.hidden).toBe(false); expect(document.body.textContent).not.toContain('SECRET_DIAGNOSTIC'); expect(invoke).toHaveBeenCalledTimes(1) })
  it('serializes repeated open actions and releases all buttons afterward', async () => { let finish!: () => void; invoke.mockImplementation(() => new Promise<void>(resolve => { finish = resolve })); document.getElementById('account-devices')!.click(); document.getElementById('account-sent')!.click(); expect(invoke).toHaveBeenCalledTimes(1); finish(); await new Promise(resolve => setTimeout(resolve, 0)); expect((document.getElementById('account-sent') as HTMLButtonElement).disabled).toBe(false) })
})
