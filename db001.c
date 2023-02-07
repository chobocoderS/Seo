#include <stdio.h>
#include <mariadb/mysql.h>
#include <string.h>

int main() {

	MYSQL	*connection=NULL, conn;
	MYSQL_RES	*sql_result;
	MYSQL_ROW	sql_row;
	int	query_stat;
	
	// column list
	//
	//MariaDB [project_db]> desc tb_member_list ;
        //+----------mysql.h+--------+------+-----+---------+----------------+
       //| Field | Type | Null | Key | Default | Extra |
        //+----------+--------+------+-----+---------+----------+
       //| id | bigint(20) | NO | PRI | NULL| auto_increment |
        //| name     | varchar(100) | YES  |     | NULL            |                |
        //| age      | int(11)      | YES  |     | NULL            |                |
       // | address  | varchar(100) | YES  |     | NULL            |                |
        //| phone    | varchar(100) | YES  |     | NULL            |                |
       // | descript | varchar(100) | YES  |     | NULL            |                |
        //+----------+--------------+------+-----+---------        +----------------+
        //6 rows in set (0.001 sec)
        
        //MariaDB [project_db]> 
	        
	int id = 0;
	char name[100] = {};
	int age = 0;
	char address[100] = {};
	char phone[100] = {};
	char descript[100] = {};

	printf("INFO: begin program\n");
	
	mysql_init(&conn);
	
	connection = mysql_real_connect(
			&conn,	// mysql handler
			"localhost",	// host
			"root",	// id
			"rootpass",	// pw
			"project_db",	// db_name
			3306,		// port
			(char*)NULL,	// 
			0		// 
		);

	if ( connection == NULL ) {
		fprintf(stderr, "ERROR: "
			"Mysql connection error: %s",
			mysql_error(&conn));
		return 1;
	}
	
	query_stat = mysql_query( connection, 
		"SELECT * FROM tb_member_list" );
	if ( query_stat != 0 ) {
		fprintf( stderr, "ERR: Mysql query error : %s",
		mysql_error(&conn) );
		return 1;
	}
	
	sql_result = mysql_store_result(connection);
	
	while ( (sql_row = mysql_fetch_row(sql_result)) 
			!= NULL ) 
	{
		printf( "%s\t%s\t%s\t%s\t%s\t%s\n", 
		sql_row[0], sql_row[1], sql_row[2], 
		sql_row[3], sql_row[4], sql_row[5] );
	}
	

	if ( sql_result != NULL ) 
	{
		mysql_free_result(sql_result);
		sql_result = NULL;
	} else {
		fprintf(stderr,
			"WARNING: "
			"sql_result is already free !!!\n");
	}
	// end of if - else .

	if ( sql_result != NULL ) 
	{
		mysql_free_result(sql_result);
		sql_result = NULL;
	} else {
		fprintf(stderr,
			"WARNING: "
			"sql_result is already free "
			"(%s:%d (%s))!!!\n",
			__FILE__, __LINE__ , __FUNCTION__);
	}
	// end of if - else .
		
	return 0;

}
