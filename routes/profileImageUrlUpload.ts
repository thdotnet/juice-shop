/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const hasProtocol = /^[a-z][a-z\d+.-]*:/i.test(url)
          if (hasProtocol && !(utils.startsWith(url, 'http://') || utils.startsWith(url, 'https://'))) {
            throw new Error('Profile image URL must use HTTP or HTTPS')
          }
          const normalizedUrl = hasProtocol ? url : `https://${url}`
          const parsedUrl = new URL(normalizedUrl)
          if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
            throw new Error('Profile image URL must use HTTP or HTTPS')
          }
          await UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: parsedUrl.toString() }) }).catch((error: Error) => { next(error) })
        } catch (error) {
          logger.warn(`Error validating user profile image URL: ${utils.getErrorMessage(error)}`)
          next(error)
          return
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
