//gsoap ns service name:	delegation
//gsoap ns service style:	rpc
//gsoap ns service encoding:	encoded
//gsoap ns service namespace:	http://www.gridsite.org/ns/delegation.wsdl
//gsoap ns service location:	http://localhost/delegserver.cgi

struct ns__putProxyResponse { } ;

//gsoap ns schema namespace: urn:delegation
int ns__getProxyReq(char *delegationID, char **request);
int ns__putProxy(char *delegationID, char *proxy, 
                 struct ns__putProxyResponse *unused);
