/**
 * Container tokens `@strutvane/auth` reads (integration map connection 2). Apps and packages bind
 * them; auth never imports the package that provides them.
 *
 * @module
 */
import { type Token, token } from '@strutvane/framework/core'
import type { AuthMailer } from './engine/ports/mailer.ts'

/**
 * Where auth sends its mails (verification, reset, email link, invitations, "password changed").
 * Bind it to your mail package or queue; every mail carries ONE secret link, so never log it.
 * Without a binding the provider drops mails with a warning that names only the mail kind.
 *
 * @example
 * app.container.value(AuthMailerToken, { send: (mail) => queue.push('auth-mail', mail) })
 */
export const AuthMailerToken: Token<AuthMailer> = token<AuthMailer>('strutvane.auth.mailer')
