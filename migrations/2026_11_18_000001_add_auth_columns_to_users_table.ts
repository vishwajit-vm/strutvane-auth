import { type Migration, migration } from '@strutvane/framework/schema'

// @strutvane/auth: the sign-in columns it needs on your `users` table. The table itself is the
// app's (the skeleton's 0001_01_01_000000_create_users_table migration owns it; decision #2), so
// auth only ADDS columns here, as an ordinary migration you can read, keep and roll back.
// `node strut auth:migration` copies this file into database/migrations; `node strut migrate`
// runs it. Auth never creates or alters `users` at runtime.
//
// - two_factor_secret: AES-256-GCM ciphertext of the TOTP secret (never the secret itself);
//   secret by name, so the API, `toJSON()` and the logs never show it.
// - two_factor_confirmed_at: when the user proved the authenticator works (2FA is enforced only
//   after that).
// - two_factor_last_step: the last TOTP time step accepted (replay protection).
// - current_team_id: the team (tenant) the user last switched to.
export default migration({
  up(schema) {
    schema.table('users', (t) => {
      t.text('two_factor_secret').nullable()
      t.timestamp('two_factor_confirmed_at').nullable().hidden()
      t.bigInteger('two_factor_last_step').nullable().hidden()
      t.string('current_team_id', 36).nullable().hidden()
    })
  },
  down(schema) {
    schema.table('users', (t) => {
      t.dropColumn(
        'two_factor_secret',
        'two_factor_confirmed_at',
        'two_factor_last_step',
        'current_team_id',
      )
    })
  },
}) as Migration
