@load base/frameworks/sumstats
global total404=0;
global total=0;
global allsusorigin:table[addr] of int =table();
global per1:double;
global per2:double;
global temp:double;
event zeek_init()
    {
    local r1 = SumStats::Reducer($stream="dns.lookup", $apply=set(SumStats::UNIQUE));
    SumStats::create([$name="dns.requests.unique",
                      $epoch=10min,
                      $reducers=set(r1),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        local r = result["dns.lookup"];
						temp=total404;
						per1=temp/total;
						temp=r$unique;
						per2=temp/total404;
                        if(total404>2&&per1>0.2&&per2>0.5)
						{
							 print fmt("%s is a scanner with %d scan attemps on %d urls", key$host, total404, r$unique);
						}
                        }]);
    }

event http_reply(c: connection, version: string, code: count, reason: string)
{
	total=total+1;
	if ( c$http$status_code == 404 )
	{
		total404=total404+1;
		SumStats::observe("dns.lookup", [$host=c$id$orig_h], [$str=c$http$uri]);
	}
}
