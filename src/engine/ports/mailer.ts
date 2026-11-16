/**
 * The mailer port: the framework renders and queues these (Laravel's queued notifications).
 *
 * Why a closed union instead of "send any template": the set of auth mails is part of the security
 * design. Each mail goes to the STORED address of the account (never the address the requester
 * typed, so case/accent look-alikes cannot redirect a reset; review F-08), and each carries exactly
 * one secret URL.
 *
 * @module
 */

/** Every mail the auth core sends. `url` is absolute and secret: never log it. */
export type AuthMail =
  | {
      readonly kind: 'password-reset'
      readonly to: string
      readonly userId: string
      readonly url: string
    }
  | {
      readonly kind: 'verify-email'
      readonly to: string
      readonly userId: string
      readonly url: string
    }
  | {
      readonly kind: 'email-link'
      readonly to: string
      readonly userId: string
      readonly url: string
    }
  | {
      /** Someone tried to register with an address that already has an account. */
      readonly kind: 'registration-attempt'
      readonly to: string
      readonly userId: string
    }
  | { readonly kind: 'password-changed'; readonly to: string; readonly userId: string }
  | {
      readonly kind: 'team-invitation'
      readonly to: string
      readonly teamName: string
      readonly role: string
      readonly url: string
    }

/**
 * Sends (or queues) one auth mail. Failures are reported to the logger and never change the HTTP
 * response, because a response that depends on delivery leaks whether the account exists.
 *
 * @example
 * ```ts
 * const mailer: AuthMailer = { send: (mail) => queue.dispatch(new SendAuthMail(mail)) }
 * ```
 */
export interface AuthMailer {
  send(mail: AuthMail): Promise<void>
}
