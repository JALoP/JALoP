#ifndef _JAL_DB_UTILS_H_
#define _JAL_DB_UTILS_H_

#ifdef __cplusplus
extern "C" {
#endif

#define JALDB_STR_HELPER(x) #x
#define JALDB_STR(x) JALDB_STR_HELPER(x)

/**
 * Macro to that will log a Berkeley DB error with the file and line number
 * @param db a DB* or DB_ENV*
 * @param err The Berkeley DB error code
 */
#define JALDB_DB_ERR(__db, __err) \
	do { \
		__db->err(__db, __err, __FILE__ "(" JALDB_STR( __LINE__ ) ")"  );\
	} while (0)
#ifdef __cplusplus
}
#endif

#endif // _JAL_DB_UTILS_H_

