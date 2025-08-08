<!-- users/authz -->
GET	    /api/roles                        private
POST	/api/roles                        private
GET	    /api/roles/{roleId}               private
DELETE	/api/roles/{roleId}               private
POST	/api/roles/{roleId}/permissions   private // it can be merge
DELETE	/api/roles/{roleId}/permissions   private // it can be merge
GET	    /api/permissions                  private

<!-- MFA: Passkeys -->
GET	    /api/users/me/passkeys                      private
POST	/api/users/me/passkeys/register-challenge   private
POST	/api/users/me/passkeys/register             private
DELETE	/api/users/me/passkeys/{passkeyId}          private
POST	/api/auth/passkey/login-challenge           public
POST	/api/auth/passkey/login                     public  
