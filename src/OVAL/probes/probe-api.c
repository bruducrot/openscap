#include "probe-api.h"

/*
 * items
 */

SEXP_t *probe_item_build (const char *fmt, ...)
{

}

SEXP_t *probe_item_creat (const char *name, SEXP_t *attrs, ...)
{

}

SEXP_t *probe_item_new (const char *name, SEXP_t *attrs)
{

}

SEXP_t *probe_item_attr_add ()
{

}

SEXP_t *probe_item_ent_add ()
{

}

/*
 * objects
 */

SEXP_t *probe_obj_build (const char *fmt, ...)
{

}

SEXP_t *probe_obj_creat (const char *name, SEXP_t *attrs, ...)
{

}

SEXP_t *probe_obj_new (const char *name, SEXP_t *attrs)
{

}


SEXP_t *probe_obj_getent (SEXP_t *obj, const char *name, uint32_t n)
{

}

int probe_obj_getentval (SEXP_t *obj, const char *name, uint32_t n, SEXP_t **res)
{

}

SEXP_t *probe_obj_getattrval (SEXP_t *obj, const char *name)
{

}

bool probe_obj_attrexists (SEXP_t *obj, const char *name)
{

}

int probe_obj_setstatus (SEXP_t *obj, int status)
{

}

int probe_obj_setentstatus (SEXP_t *obj, const char *name, uint32_t n, int status)
{

}

/*
 * entities
 */

int probe_ent_getval (SEXP_t *ent, SEXP_t **res)
{

}

SEXP_t *probe_ent_getattrval (SEXP_t *ent, const char *name)
{

}

bool probe_ent_attrexists (SEXP_t *ent, const char *name)
{

}

oval_datatype_t probe_ent_setdatatype (SEXP_t *ent)
{

}

oval_datatype_t probe_ent_getdatatype (SEXP_t *ent)
{

}

int probe_ent_setmask (SEXP_t *ent, bool mask)
{

}

bool probe_ent_getmask (SEXP_t *ent)
{

}

int probe_ent_setstatus (SEXP_t *ent, int status)
{

}

int probe_ent_getstatus (SEXP_t *ent)
{

}

char *probe_ent_getname (const SEXP_t *ent)
{

}

char *probe_ent_getname_r (const SEXP_t *ent, char *buffer, size_t buflen)
{

}
