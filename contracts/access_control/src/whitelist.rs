use crate::admin::require_admin;
use crate::types::AccessControlError;
use soroban_sdk::{symbol_short, Address, Env, Symbol};

pub const WL_EN: Symbol = symbol_short!("WL_EN");
pub const WL: Symbol = symbol_short!("WL");

/// Sets whether whitelist enforcement is active.
pub fn set_whitelist_enabled(
    env: &Env,
    caller: &Address,
    enabled: bool,
) -> Result<(), AccessControlError> {
    require_admin(env, caller)?;
    env.storage().instance().set(&WL_EN, &enabled);
    Ok(())
}

/// Returns whether whitelist enforcement is currently enabled.
pub fn is_whitelist_enabled(env: &Env) -> bool {
    env.storage().instance().get(&WL_EN).unwrap_or(false)
}

/// Adds an address to the authorized whitelist.
pub fn add_to_whitelist(
    env: &Env,
    caller: &Address,
    user: &Address,
) -> Result<(), AccessControlError> {
    require_admin(env, caller)?;
    env.storage().persistent().set(&(WL, user.clone()), &true);
    Ok(())
}

/// Removes an address from the authorized whitelist.
pub fn remove_from_whitelist(
    env: &Env,
    caller: &Address,
    user: &Address,
) -> Result<(), AccessControlError> {
    require_admin(env, caller)?;
    env.storage().persistent().remove(&(WL, user.clone()));
    Ok(())
}

/// Checks whether `user` is on the whitelist.
/// If whitelist is disabled, returns `true`.
pub fn check_whitelist(env: &Env, user: &Address) -> bool {
    if !is_whitelist_enabled(env) {
        return true;
    }
    env.storage()
        .persistent()
        .get(&(WL, user.clone()))
        .unwrap_or(false)
}

/// Returns raw status of user on whitelist without checking `is_whitelist_enabled`.
pub fn is_whitelisted(env: &Env, user: &Address) -> bool {
    env.storage()
        .persistent()
        .get(&(WL, user.clone()))
        .unwrap_or(false)
}
