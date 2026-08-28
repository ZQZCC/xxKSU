bool only_manager(void)
{
	return is_manager();
}

bool only_root(void)
{
	return current_uid().val == 0;
}

bool manager_or_root(void)
{
	return current_uid().val == 0 || is_manager();
}

bool always_allow(void)
{
	return true;
}

bool allowed_for_su(void)
{
	return is_manager() || ksu_is_allow_uid_for_current(current_uid().val);

}

#ifdef CONFIG_KSU_CAPFD_ROOT
bool capfd_issuer_allowed(void)
{
	return uid_eq(current_euid(), GLOBAL_ROOT_UID) && is_ksu_domain();
}
#endif
