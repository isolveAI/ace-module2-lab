/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import vm from 'node:vm'
import { type Request, type Response, type NextFunction } from 'express'
// @ts-expect-error FIXME due to non-existing type definitions for notevil
import { eval as safeEval } from 'notevil'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

function hasDisallowedPatterns (data: any): boolean {
  let str = ''
  if (typeof data === 'string') {
    str = data
  } else {
    try {
      str = JSON.stringify(data) ?? ''
    } catch {
      return true
    }
  }

  let normalized = str
    .replace(/\\u\{([0-9a-fA-F]+)\}/g, (_, hex) => {
      try { return String.fromCodePoint(parseInt(hex, 16)) } catch { return '' }
    })
    .replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => {
      try { return String.fromCharCode(parseInt(hex, 16)) } catch { return '' }
    })
    .replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => {
      try { return String.fromCharCode(parseInt(hex, 16)) } catch { return '' }
    })

  let prev = ''
  while (prev !== normalized) {
    prev = normalized
    normalized = normalized.replace(/['"`]\s*\+\s*['"`]/g, '')
  }

  const disallowedPatterns = [
    /constructor/i,
    /__proto__/i,
    /prototype/i,
    /getPrototypeOf/i,
    /getOwnProperty/i,
    /setPrototypeOf/i,
    /\bprocess\b/i,
    /mainModule/i,
    /\brequire\b/i,
    /child_process/i,
    /\bexec(Sync|File|FileSync)?\b/i,
    /\bspawn(Sync)?\b/i,
    /\bFunction\b/,
    /\bglobal(This)?\b/i,
    /\bimport\b/i,
    /\beval\b/i,
    /\bcallee\b/i,
    /\bcaller\b/i,
    /fromCharCode/i,
    /fromCodePoint/i,
    /\bBuffer\b/,
    /\bReflect\b/,
    /\bProxy\b/,
    /\$\{/
  ]

  if (disallowedPatterns.some(pattern => pattern.test(str) || pattern.test(normalized))) {
    return true
  }

  try {
    const uriDecoded = decodeURIComponent(str)
    if (disallowedPatterns.some(pattern => pattern.test(uriDecoded))) {
      return true
    }
  } catch {}

  return false
}

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    if (utils.isChallengeEnabled(challenges.rceChallenge) || utils.isChallengeEnabled(challenges.rceOccupyChallenge)) {
      const orderLinesData = body.orderLinesData || ''
      try {
        if (hasDisallowedPatterns(orderLinesData)) {
          throw new Error('Sandbox breakout attempt detected')
        }
        const sandbox = { safeEval, orderLinesData }
        vm.createContext(sandbox)
        vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })
        res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
      } catch (err) {
        if (utils.getErrorMessage(err).match(/Script execution timed out.*/) != null) {
          challengeUtils.solveIf(challenges.rceOccupyChallenge, () => { return true })
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          challengeUtils.solveIf(challenges.rceChallenge, () => { return utils.getErrorMessage(err) === 'Infinite loop detected - reached max iterations' })
          next(err)
        }
      }
    } else {
      res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
    }
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
