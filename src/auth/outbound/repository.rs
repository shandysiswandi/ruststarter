use async_trait::async_trait;

use crate::{
    app::error::AppError,
    auth::domain::entity::{
        mfa::MfaFactor,
        oauth::OAuthUserProfile,
        user::{User, UserUpdatePayload},
        user_connection::UserConnection,
        user_credential::UserCredential,
    },
};

#[async_trait]
#[cfg_attr(test, mockall::automock)]
pub trait AuthRepository: Send + Sync {
    /// Finds a single user by their unique ID.
    ///
    /// # Arguments
    ///
    /// * `id` - The numeric ID of the user to fetch.
    ///
    /// # Returns
    ///
    /// * `Ok(Some(User))` if a matching, non-deleted user is found.
    /// * `Ok(None)` if no user matches the given ID.
    /// * `Err(AppError)` if a database or mapping error occurs.
    async fn find_user_by_id(&self, id: i64) -> Result<Option<User>, AppError>;

    /// Finds a single user by their unique email.
    ///
    /// # Arguments
    ///
    /// * `email` - The email of the user to fetch.
    ///
    /// # Returns
    ///
    /// * `Ok(Some(User))` if a matching, non-deleted user is found.
    /// * `Ok(None)` if no user matches the given email.
    /// * `Err(AppError)` if a database or mapping error occurs.
    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, AppError>;

    /// Retrieves a paginated list of all active (non-deleted) users.
    ///
    /// Users are ordered by their creation date in descending order (newest first).
    ///
    /// # Arguments
    ///
    /// * `page` - The zero-based page index to retrieve.
    /// * `per_page` - The maximum number of users to return per page.
    ///
    /// # Returns
    ///
    /// * `Ok((Vec<User>, u64))` - A tuple containing the list of users for the requested page
    ///   and the total number of matching users.
    /// * `Err(AppError)` - If the query fails due to a database or internal error.
    async fn find_all_users(&self, page: u64, per_page: u64) -> Result<(Vec<User>, u64), AppError>;

    /// Updates an existing user’s profile or status.
    ///
    /// # Arguments
    ///
    /// * `payload` - A `UserUpdatePayload` containing the updated user fields.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the update was successful.
    /// * `Err(AppError)` if the user could not be updated (e.g., not found or DB error).
    async fn update_user(&self, payload: UserUpdatePayload) -> Result<(), AppError>;

    /// Retrieves the stored authentication credentials for a specific user.
    ///
    /// This is typically used when performing authentication or updating
    /// a user's password, and it ensures that credential data is only fetched
    /// for the correct user.
    ///
    /// # Arguments
    ///
    /// * `uid` - The unique ID of the user whose credentials should be retrieved.
    ///
    /// # Returns
    ///
    /// * `Ok(Some(UserCredential))` - If credentials exist for the given user.
    /// * `Ok(None)` - If no credentials are found.
    /// * `Err(AppError)` - If the database query fails.
    async fn find_user_credential_by_user_id(&self, uid: i64) -> Result<Option<UserCredential>, AppError>;

    /// Creates a new user along with their associated credential record
    /// in a single transaction.
    ///
    /// # Arguments
    ///
    /// * `user` - The `User` entity containing user data.
    /// * `password` - The password for the user (will typically be hashed before persistence).
    ///
    /// # Returns
    ///
    /// * `Ok(())` if both user and credential were created successfully.
    /// * `Err(AppError)` If the operation failed at any stage.
    async fn create_user_with_credential(&self, user: User, password: String) -> Result<(), AppError>;

    /// Updates the stored credential (password) for a given user.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The unique ID of the user whose credential is being updated.
    /// * `new_password` - The new password to store (will typically be hashed before persistence).
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the credential update was successful.
    /// * `Err(AppError)` if the update failed (e.g., not found or DB error).
    async fn update_user_credential(&self, user_id: i64, new_password: &str) -> Result<(), AppError>;

    /// Retrieves all linked third-party authentication connections for a given user.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The unique ID of the user whose connections are being fetched.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<UserConnection>)` containing zero or more connections if successful.
    /// * `Err(AppError)` if a database query or mapping error occurs.
    async fn find_user_connections_by_user_id(&self, user_id: i64) -> Result<Vec<UserConnection>, AppError>;

    /// Finds an existing user connection matching the given provider details,
    /// or creates a new one if none exists.
    ///
    /// # Arguments
    ///
    /// * `payload` - A `OAuthUserProfile` entity containing the provider, provider user ID,
    ///   and any associated authentication tokens or scopes.
    ///
    /// # Returns
    ///
    /// * `Ok(User)` - The user associated with the connection, whether found or newly created.
    /// * `Err(AppError)` - If a database query or insertion error occurs.
    async fn find_or_create_oauth_user(&self, payload: OAuthUserProfile) -> Result<User, AppError>;

    /// Deletes an OAuth user connection for a specific user.
    ///
    /// This is typically used to remove a linked third-party account (e.g., Google, GitHub)
    /// from an existing user profile.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The unique ID of the user who owns the OAuth connection.
    /// * `connection_id` - The unique ID of the OAuth connection record to delete.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the connection was successfully deleted.
    /// * `Err(AppError)` - If the delete operation failed (e.g., connection not found, DB error).
    async fn delete_oauth_user(&self, user_id: i64, connection_id: i64) -> Result<(), AppError>;

    /// Retrieves all registered multi-factor authentication (MFA) factors for a specific user.
    ///
    /// This method queries the database for all MFA factor records associated with the given user ID.
    /// MFA factors can include items such as TOTP authenticators, security keys, or backup codes.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The unique ID of the user whose MFA factors will be retrieved.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<MfaFactor>)` - A list of MFA factors associated with the user.  
    /// * `Err(AppError)` - If the query fails due to a database or internal error.
    async fn find_mfa_factors_by_user_id(&self, user_id: i64) -> Result<Vec<MfaFactor>, AppError>;

    /// Retrieves a specific multi-factor authentication (MFA) factor by ID and User ID.
    ///
    /// This is typically used during MFA enrollment when a factor has been created
    /// but not confirmed (e.g., before a TOTP secret or security key registration is validated).
    ///
    /// # Arguments
    ///
    /// * `user_id` - The unique ID of the user who owns the MFA factor.
    /// * `factor_id` - The unique ID of the MFA factor to retrieve.
    ///
    /// # Returns
    ///
    /// * `Ok(Some(MfaFactor))` - If the unverified MFA factor exists and belongs to the user.
    /// * `Ok(None)` - If no matching unverified factor is found.
    /// * `Err(AppError)` - If the query fails due to a database or internal error.
    async fn find_unverified_mfa_factor_by_id_and_user_id(
        &self,
        user_id: i64,
        factor_id: i64,
    ) -> Result<Option<MfaFactor>, AppError>;

    /// Creates a new multi-factor authentication (MFA) factor record for a given user.
    ///
    /// This is typically used during MFA enrollment to persist a new factor
    /// (e.g., TOTP, WebAuthn, SMS) in the database before it is verified.
    /// The `MfaFactor` domain object should contain all required details such as
    /// the associated user ID, factor type, secret or credential data, and a
    /// friendly display name.
    ///
    /// # Arguments
    ///
    /// * `factor` - A fully populated `MfaFactor` domain object representing the MFA factor to store.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the MFA factor was successfully created.
    /// * `Err(AppError)` - If the creation fails due to a database or internal error.
    async fn create_mfa_factor(&self, factor: MfaFactor) -> Result<(), AppError>;

    /// Marks an existing multi-factor authentication (MFA) factor as verified.
    ///
    /// This is typically called after a user successfully completes the MFA setup
    /// process (e.g., entering a correct TOTP code for the first time), indicating
    /// that the factor is now active and can be used for authentication.
    ///
    /// # Arguments
    ///
    /// * `factor_id` - The unique ID of the MFA factor to verify.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the factor was successfully marked as verified.
    /// * `Err(AppError)` - If the factor does not exist or the update fails.
    async fn verify_mfa_factor(&self, factor_id: i64) -> Result<(), AppError>;

    /// Deletes a specific multi-factor authentication (MFA) factor for a given user.
    ///
    /// This is typically used when a user disables an MFA method such as a TOTP authenticator,
    /// security key, or backup code.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The unique ID of the user who owns the MFA factor.
    /// * `factor_id` - The unique ID of the MFA factor record to delete.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the MFA factor was successfully deleted.
    /// * `Err(AppError)` - If the delete operation failed (e.g., factor not found, DB error).
    async fn delete_mfa_factor_by_id(&self, user_id: i64, factor_id: i64) -> Result<(), AppError>;

    /// Sets the roles for a specific user.
    ///
    /// This method replaces any existing roles assigned to the user with the provided list.
    /// Typically used in administrative contexts to manage user permissions.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The unique identifier of the user whose roles are being updated.
    /// * `role_ids` - A list of role IDs to assign to the user. Existing roles will be replaced.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the operation is successful.
    /// * `Err(AppError)` if an error occurs while updating the roles.
    async fn set_user_roles(&self, user_id: i64, role_ids: Vec<i64>) -> Result<(), AppError>;

    /// Checks whether all specified roles exist.
    ///
    /// This method verifies that every role ID in the provided slice corresponds
    /// to an existing role in the system.
    ///
    /// # Arguments
    ///
    /// * `role_ids` - A slice of role IDs to check.
    ///
    /// # Returns
    ///
    /// * `Ok(true)` if all roles exist.
    /// * `Ok(false)` if one or more roles do not exist.
    /// * `Err(AppError)` if an error occurs during the check.
    async fn roles_exist(&self, role_ids: &[i64]) -> Result<bool, AppError>;
}
