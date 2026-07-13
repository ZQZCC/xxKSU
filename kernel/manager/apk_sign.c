#ifndef KSU_MANAGER_PACKAGE
#define KSU_MANAGER_PACKAGE "ka.super"
#endif

int get_pkg_from_apk_path(char *pkg, const char *path)
{
	int len = strlen(path);
	if (len >= KSU_MAX_PACKAGE_NAME || len < 1)
		return -1;

	const char *last_slash = NULL;
	const char *second_last_slash = NULL;

	int i;
	for (i = len - 1; i >= 0; i--) {
		if (path[i] == '/') {
			if (!last_slash) {
				last_slash = &path[i];
			} else {
				second_last_slash = &path[i];
				break;
			}
		}
	}

	if (!last_slash || !second_last_slash)
		return -1;

	const char *last_hyphen = strchr(second_last_slash, '-');
	if (!last_hyphen || last_hyphen > last_slash)
		return -1;

	int pkg_len = last_hyphen - second_last_slash - 1;
	if (pkg_len >= KSU_MAX_PACKAGE_NAME || pkg_len <= 0)
		return -1;

	memcpy(pkg, second_last_slash + 1, pkg_len);
	pkg[pkg_len] = '\0';

	return 0;
}

bool is_manager_apk(char *path)
{
	char pkg[KSU_MAX_PACKAGE_NAME];
	if (get_pkg_from_apk_path(pkg, path) < 0) {
		pr_err("Failed to get package name from apk path: %s\n", path);
		return false;
	}

	if (strncmp(pkg, KSU_MANAGER_PACKAGE, sizeof(KSU_MANAGER_PACKAGE))) {
		return false;
	}

	return true;
}
