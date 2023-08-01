# GraphQL Notes

## GraphQL Endpoints

/graphql/graphiql  
/graphql/graphiql.php  
/graphql/console  
/graphql.php  
/api/gql  

## Authentication

GraphQL implementation doesn’t require or enforce, any kind of authentication. This is up to the developer. Often the developers are in a hurry because of time limitations thus they postpone security-stuff.

## GraphQL Introspection

query {\n  __schema {\n    types {\n      name\n      fields {\n        name\n      }\n    }\n  }\n}

## Tools

### GraphQL Raider (Burpsuite)

Makes GraphQL requests easier to view and modify.  

### InQL – Introspection GraphQL Scanner (Burpsuite)

HIGHLY RECOMMENDED  
Automates introspection queries and maps out all possible requests for easy copy-pasta into Repeater.  

Hacker’s One – Introspection and Parsing through InQL Scanner
GraphQL Voyager Visualizer Tool

Tool: https://ivangoncharov.github.io/graphql-voyager/

This tool allows for visualizing a GraphQL by providing the output of the introspection query. It is very useful, interactive and provides a special way of visualizing the data (like the phpMyAdmin’s database designer).
GraphQL Voyager


## Other Interesting Tools

    https://github.com/swisskyrepo/GraphQLmap
    https://github.com/andev-software/graphql-ide

## GraphQL References:

    https://raz0r.name/articles/looting-graphql-endpoints-for-fun-and-profit/
    https://medium.com/@ignaciochiazzo/introspection-in-graphql-a5a5bd744a66
    https://prog.world/pentest-applications-with-graphql/
    https://blog.doyensec.com/2018/05/17/graphql-security-overview.html
    https://raz0r.name/articles/why-you-should-not-use-graphql-schema-generators/#more-910
    https://devhints.io/graphql
    https://medium.com/@localh0t/discovering-graphql-endpoints-and-sqli-vulnerabilities-5d39f26cea2e
    https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql
    https://graphql.org/learn/queries/
