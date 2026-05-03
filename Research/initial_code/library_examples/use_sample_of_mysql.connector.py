import mysql.connector

#Use mysql.connector to connect your database
mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    passwd="" #Your password here
)

mycursor = mydb.cursor()

#Creat a database called mydb, also can change the name you want
mycursor.execute("CREATE DATABASE mydb") 

#Show the list of database
mycursor.execute("SHOW DATABASES")

#Creat a new data table
mycursor.execute("CREATE TABLE test (letters VARCHAR(255), numbers VARCHAR(255))")

#To check whether the table is exist
mycursor.execute("SHOW TABLES")

#Creat a primary key when have created a table test
mycursor.execute("ALTER TABLE test ADD COLUMN id INT AUTO_INCREMENT PRIMARY KEY")

#Insert the data
sql = "INSERT INTO test (letters, numbers) VALUES (%s, %s)"
val = ("A", "1")
mycursor.execute(sql, val)
mydb.commit() #Must used this func when update the table

sql1 = "INSERT INTO test (letters, numbers) VALUES (%s, %s)"
val1 = [
    ("A", "1")
    ("B", "2")
    ("C", "3")
    ("D", "4")
]
mycursor.executemany(sql, val)
mydb.commit()

#Select the data
mycursor.execute("SELECT * FROM test")
myresult = mycursor.fetchall()
for x in myresult:
    print(x)

mycursor.execute("SELECT letters, numbers FROM test")
myresult1 = mycursor.fetchall()
for x in myresult1:
    print(x)

mycursor.execute("SELECT * FROM test")
myresult2 = mycursor.fetchone()
print(myresult2)

sql3 = "SELECT * FROM test WHERE letters = %s"
val3 = ("A")
mycursor.execute(sql3, val3)
myresult3 = mycursor.fetchall()
for x in myresult3:
    print(x)

#Sort the data, sort in ascending order by default, which keyword is "ASC"
#Also can make descending sort with keyword "DESC"  -> sql = "SELECT * FROM test ORDER BY letters DESC"
sql4 = "SELECT * FROM test ORDER BY letters"
mycursor.execute(sql4)
myresult = mycursor.fetchall()

#Set the numbers of the data we want to select
mycursor.execute("SELECT * FROM test LIMIT 3") #select the first 3 data
myresult4 = mycursor.fetchall()

mycursor.execute("SELECT * FROM test LIMIT 3 OFFSET 1") #begin at the second data

#Delete the data
sql5 = "DELETE FROM test WHERE letters = %s"
val5 = ("C", )
mycursor.execute(sql, val5)
mydb.commit()

#Update the data in the table
sql6 = "UPDATE sites SET name = %s WHERE name = %s"
val6 = ("D", "E")
mycursor.execute(sql, val)
mydb.commit()

#Delete the table
sql = "DROP TABLE IF EXISTS test"  # Delete the data table test, "IF EXISTS" is to judge that whether the table is exist
mycursor.execute(sql)

#Connect to the database directly
mydb1 = mysql.connector.connect(
    host="localhost",
    user="root",
    passwd="", #Your password here
    database="" #Your database name here
)
