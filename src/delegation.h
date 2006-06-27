//gsoap ns schema namespace:   http://www.gridsite.org/namespaces/delegation-1

struct ns__DelegationExceptionType
{
   char *message;	//nillable
};
    
struct ns__NewProxyReq
{
   char *proxyRequest;	//nillable
   char *delegationID;	//nillable
};

struct _DelegationException
{
   struct ns__DelegationExceptionType *ns__DelegationException;
};

//gsoap ns service name:	DelegationSoapBinding
//gsoap ns service type:	Delegation
//gsoap ns service port:	https://localhost/gridsite-delegation.cgi
//gsoap ns service namespace:	http://www.gridsite.org/namespaces/delegation-1

/* *** getProxyReq method *** */

//gsoap ns service method-style:	rpc
//gsoap ns service method-encoding:	literal
//gsoap ns service method-action:	""
//gsoap ns service method-fault:	getProxyReq _DelegationException

int ns__getProxyReq(char *_delegationID, 
                    struct ns__getProxyReqResponse {
                                    char *getProxyReqReturn; } *);

/* *** getNewProxyReq method *** */

//gsoap ns service method-style:	getNewProxyReq rpc
//gsoap ns service method-encoding:	getNewProxyReq literal
//gsoap ns service method-action:	getNewProxyReq ""
//gsoap ns service method-fault:	getNewProxyReq _DelegationException

int ns__getNewProxyReq(struct ns__getNewProxyReqResponse {
                         struct ns__NewProxyReq *getNewProxyReqReturn; } *);
  
/* *** renewProxyReq method *** */

//gsoap ns service method-style:	renewProxyReq rpc
//gsoap ns service method-encoding:	renewProxyReq literal
//gsoap ns service method-action:	renewProxyReq ""
//gsoap ns service method-fault:	renewProxyReq _DelegationException

int ns__renewProxyReq(char *_delegationID,
                      struct ns__renewProxyReqResponse {
                                          char *_renewProxyReqReturn; } *);

/* *** putProxy method *** */

//gsoap ns service method-style:	putProxy rpc
//gsoap ns service method-encoding:	putProxy literal
//gsoap ns service method-action:	putProxy ""
//gsoap ns service method-fault:	putProxy _DelegationException

int ns__putProxy(char *_delegationID, 
                 char *_proxy,
                 struct ns__putProxyResponse { } *);

/* *** getTerminationTime method *** */

//gsoap ns service method-style:	getTerminationTime rpc
//gsoap ns service method-encoding:	getTerminationTime literal
//gsoap ns service method-action:	getTerminationTime ""
//gsoap ns service method-fault:	getTerminationTime _DelegationException

int ns__getTerminationTime(char *_delegationID,
                           struct ns__getTerminationTimeResponse {
                                     time_t _getTerminationTimeReturn; } *);
                                     
/* *** destroy method *** */

//gsoap ns service method-style:	destroy rpc
//gsoap ns service method-encoding:	destroy literal
//gsoap ns service method-action:	destroy ""
//gsoap ns service method-fault:	destroy _DelegationException

int ns__destroy(char *_delegationID,
                struct ns__destroyResponse { } *);
