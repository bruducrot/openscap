/**
 * @file   apparmorstatus.c
 * @brief  apparmorstatus probe
 * @author "Bruno Ducrot" <bruno@poupinou.org>
 *
 */

/*
 * Copyright 2017 Bruno Ducrot
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *   Bruno Ducrot <bruno@poupinou.org>
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <fnmatch.h>

#include "seap.h"
#include "probe-api.h"
#include "probe/entcmp.h"
#include "common/debug_priv.h"

#define SYS_AA_PATH "/sys/module/apparmor"

#define AA_MODE_UNCONFINED 0
#define AA_MODE_ENFORCE 1
#define AA_MODE_COMPLAIN 2

struct aa_status {
	int loaded;
	int enabled;
	int64_t loaded_profiles;
	int64_t enforce_mode_profiles;
	int64_t complain_mode_profiles;
	int64_t processes_with_profiles;
	int64_t enforce_mode_processes;
	int64_t complain_mode_processes;
	int64_t unconfined_processes_with_profiles;
};

struct aa_profile {
	char *glob;
	int aa_mode;
};

static int aa_isloaded(void)
{
	struct stat st;

	return (!stat(SYS_AA_PATH, &st) && S_ISDIR(st.st_mode));
}

static int aa_isenabled(void)
{
	int fd;
	char status;

	fd = open(SYS_AA_PATH "/parameters/enabled", O_RDONLY);

	if (fd == -1) {
		return 0;
	}

	(void) read(fd, &status, 1);
	close(fd);

	return status == 'Y';
}

static int aa_find_securityfs(char *securityfs)
{
	FILE *file;
	char buf[PATH_MAX];
	char *p, *mount_point, *fs_type;

	file = fopen("/proc/mounts", "r");

	if (!file) {
		return 0;
	}

	while (fgets(buf, PATH_MAX, file) && !feof(file)) {
		p = strchr(buf, ' ');
		if (!p)
			continue;
		mount_point = p + 1;
		p = strchr(mount_point, ' ');
		if (!p)
			continue;
		*p = 0;
		fs_type = p + 1;
		p = strchr(fs_type, ' ');
		if (!p)
			continue;
		*p = 0;

		if (strcmp("securityfs", fs_type) == 0) {
			strcpy(securityfs, mount_point);
			break;
		}
	}

	fclose(file);

	return 1;
}

static void init_aa_status(struct aa_status *s)
{
	s->loaded = -1;
	s->enabled = -1;
	s->loaded_profiles = 0;
	s->enforce_mode_profiles = 0;
	s->complain_mode_profiles = 0;
	s->processes_with_profiles = 0;
	s->enforce_mode_processes = 0;
	s->complain_mode_processes = 0;
	s->unconfined_processes_with_profiles = 0;
}

static int get_aa_processes(struct aa_status *status, struct aa_profile *pro, ssize_t aa_profile_count)
{
	DIR *dp;
	struct dirent *ep;     
	dp = opendir ("/proc");

	if (!dp) {
		return -1;
	}

	char *end;

	char buf[PATH_MAX];
	FILE *file;
	char *p;

	while ((ep = readdir(dp))) {
		strtol(ep->d_name, &end, 10);
		if (ep->d_name == end)
			continue;

		sprintf(buf, "/proc/%s/attr/current", ep->d_name);
		file = fopen(buf, "r");
		if (!file)
			continue;
		if (!fgets(buf, PATH_MAX, file)) {
			fclose(file);
			continue;
		}

		fclose(file);
		buf[strlen(buf) - 1] = 0;
		if (!strcmp("unconfined", buf)) {
			char *path;

			sprintf(buf, "/proc/%s/exe", ep->d_name);

			if ((path = realpath(buf, NULL)) != NULL) {
				int i;

				for (i = 0; i < aa_profile_count; ++i) {
					if (!fnmatch(pro[i].glob, path, 0)) {
						(status->unconfined_processes_with_profiles)++;
						break;
					}
				}
				free(path);
			}

		} else {
			(status->processes_with_profiles)++;
			p = strrchr(buf, '(');
			if (!p) {
				fclose(file);
				continue;
			}
			switch (*(p + 1)) {
			case 'e':
				(status->enforce_mode_processes)++;
				break;
			case 'c':
				(status->complain_mode_processes)++;
				break;
			default:
				break;
			}
		}
	}

	closedir(dp);

	return 0;
}


static int get_aa_status(struct aa_status *status, char *securityfs)
{
	int rv;
	int i;
	char buf[PATH_MAX];
	struct aa_profile *pro = NULL;
	struct aa_profile *pro_tmp = NULL;
	ssize_t pro_count;
	FILE *file;

	char *s, *p;

	sprintf(buf, "%s/apparmor/profiles", securityfs);

	file = fopen(buf, "r");
	if (!file) {
		return -1;
	}

	pro_count = 50;
	pro = realloc(pro, pro_count * sizeof pro[0]);
	if (!pro) {
		rv = -1;
		goto out1;
	}

	while (fgets(buf, PATH_MAX, file) && !feof(file)) {
		p = strrchr(buf, ' ');
		if (!p)
			continue;
		*p = 0;
		s = p + 2;

		p = strrchr(s, ')');
		if (!p || *(p + 1) != '\n')
			continue;
		*p = 0;

		pro[status->loaded_profiles].glob = strdup(buf);

		if (*s == 'c') {
			(status->complain_mode_profiles)++;
			pro[status->loaded_profiles].aa_mode = AA_MODE_COMPLAIN;
		}
		else if (*s == 'e') {
			(status->enforce_mode_profiles)++;
			pro[status->loaded_profiles].aa_mode = AA_MODE_ENFORCE;
		}
		(status->loaded_profiles)++;
		if (status->loaded_profiles >= pro_count) {
			pro_count += 50;
			pro_tmp = realloc(pro, pro_count * sizeof pro[0]);
			if (!pro_tmp) {
				rv = -1;
				goto out2;
			}
			pro = pro_tmp;
		}
	}
	rv = get_aa_processes(status, pro, status->loaded_profiles);

out2:
	for (i = 0; i < status->loaded_profiles; ++i)
		free(pro[i].glob);
	free(pro);
out1:
	fclose(file);

	return rv;
}

void *probe_init(void)
{
        /* initialize stuff */
        return (NULL);
}

void probe_fini(void *probe_arg)
{
        /* cleanup stuff */
        return;
}

static int report_aa_results(struct aa_status *status, probe_ctx *ctx)
{
	SEXP_t *item;

	item = probe_item_create(OVAL_LINUX_APPARMORSTATUS, NULL,
			"loaded_profiles_count",	OVAL_DATATYPE_INTEGER, status->loaded_profiles,
			"enforce_mode_profiles_count",	OVAL_DATATYPE_INTEGER, status->enforce_mode_profiles,
			"complain_mode_profiles_count",	OVAL_DATATYPE_INTEGER, status->complain_mode_profiles,
			"processes_with_profiles_count",	OVAL_DATATYPE_INTEGER, status->processes_with_profiles,
			"enforce_mode_processes_count",	OVAL_DATATYPE_INTEGER, status->enforce_mode_processes,
			"complain_mode_processes_count",	OVAL_DATATYPE_INTEGER, status->complain_mode_processes,
			"unconfined_processes_with_profiles_count",	OVAL_DATATYPE_INTEGER, status->unconfined_processes_with_profiles,
			NULL);
	probe_item_collect(ctx, item);

	// SEXP_free(item);


	return 0;
}


int probe_main(probe_ctx *ctx, void *probe_arg)
{
	SEXP_t *obj;
	oval_schema_version_t over;

	char securityfs[PATH_MAX];
	struct aa_status status;
	int rv = 0;


	obj = probe_ctx_getobject(ctx);
	if (obj == NULL)
		return PROBE_ENOOBJ;

	over = probe_obj_get_platform_schema_version(obj);

	init_aa_status(&status);

	if ((status.loaded = aa_isloaded()) == 0) {
		probe_cobj_set_flag(probe_ctx_getresult(ctx), SYSCHAR_FLAG_NOT_APPLICABLE);
                return 0;
	}

	if ((status.enabled = aa_isenabled()) == 0) {
		probe_cobj_set_flag(probe_ctx_getresult(ctx), SYSCHAR_FLAG_NOT_APPLICABLE);
                return 0;
	}

	if (!aa_find_securityfs(securityfs)) {
		return PROBE_EFATAL;
	}

	rv = get_aa_status(&status, securityfs);

	if (rv != 0) {
		return PROBE_ENOENT;
	}
	rv = report_aa_results(&status, ctx);

        return rv;
}
