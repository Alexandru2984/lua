// Explicitly illustrative. Never stored in the live database or workspace stats.
export const demo = {
  id:'demo', target:'example.com', timestamp:'2026-01-15 10:30:00', status:'completed', profile:'deep', duration_ms:2400,
  report:{target:'example.com',profile:'deep',ip:'93.184.215.14',score:75,errors:[],
    dns:{records:[{type:'A',name:'example.com',value:'93.184.215.14',ttl:3600},{type:'AAAA',name:'example.com',value:'2606:2800:220:1:248:1893:25c8:1946',ttl:3600},{type:'MX',name:'example.com',value:'mail.example.com',priority:10,ttl:3600},{type:'NS',name:'example.com',value:'ns1.example.com',ttl:86400},{type:'TXT',name:'example.com',value:'v=spf1 -all',ttl:3600},{type:'DMARC',name:'_dmarc.example.com',value:'v=DMARC1; p=reject',ttl:3600}]},
    http:{status:200,scheme:'https',elapsed_ms:124,tls:{verified:true,hostname:'example.com'},headers:{'content-type':'text/html; charset=utf-8','strict-transport-security':'max-age=31536000; includeSubDomains','x-content-type-options':'nosniff','x-frame-options':'DENY','referrer-policy':'strict-origin-when-cross-origin','permissions-policy':'camera=(), microphone=()'},checks:[
      {key:'strict-transport-security',label:'HSTS',state:'pass',value:'max-age=31536000; includeSubDomains',advice:'A year of HTTPS enforcement is configured.'},
      {key:'content-security-policy',label:'Content Security Policy',state:'missing',advice:'Restrict allowed sources with a Content-Security-Policy header.'},
      {key:'x-content-type-options',label:'Content type protection',state:'pass',value:'nosniff',advice:'Browsers are instructed to respect declared content types.'},
      {key:'frame-protection',label:'Frame protection',state:'pass',value:'DENY',advice:'This response cannot be embedded in a frame.'},
      {key:'referrer-policy',label:'Referrer policy',state:'pass',value:'strict-origin-when-cross-origin',advice:'Cross-origin requests send the origin rather than a full path.'},
      {key:'permissions-policy',label:'Permissions policy',state:'pass',value:'camera=(), microphone=()',advice:'Unused camera and microphone permissions are disabled.'},
      {key:'https',label:'Verified HTTPS',state:'pass',value:'Certificate chain and hostname verified',advice:'A trusted certificate matches this hostname.'}],
      resources:[{path:'/robots.txt',status:200,found:true},{path:'/sitemap.xml',status:200,found:true},{path:'/.well-known/security.txt',status:404,found:false}]},
    transparency:{names:['example.com','mail.example.com','www.example.com'],source:'crt.sh'},
    registration:{name:'EXAMPLE.COM',source:'Illustrative RDAP response',status:['client transfer prohibited'],events:[{action:'registration',date:'1995-08-14T04:00:00Z'},{action:'expiration',date:'2027-08-13T04:00:00Z'}]}}
};
demo.report.dns.insights=[
  {key:'spf',label:'SPF policy',state:'observed',summary:'An explicit -all fail mechanism was observed.',value:'v=spf1 -all',advice:'Illustrative direct TXT observation; SPF includes and sending IPs are not evaluated.'},
  {key:'dmarc',label:'DMARC policy',state:'observed',summary:'A direct p=reject policy was observed.',value:'v=DMARC1; p=reject',advice:'Only a direct policy is illustrated. Parent policy, alignment and message authentication are not evaluated.'},
  {key:'caa',label:'CAA records',state:'info',summary:'No direct CAA records were observed; a parent policy may apply.',advice:'Presence or absence alone does not establish effective issuance restrictions.'},
  {key:'mx',label:'Mail routing',state:'observed',summary:'One mail exchanger was observed.',value:'10 mail.example.com',advice:'No mail server connections or delivery tests are made.'}
];
