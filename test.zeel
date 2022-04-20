export { 
	global ip: table[addr] of set[string]; 
} 

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
	if (to_lower(name) == "user-agent") {
		if (c$http$id$orig_h in ip)
		{
			if (value !in ip[c$http$id$orig_h])
			{
				add ip[c$http$id$orig_h][value];
				if (|ip[c$http$id$orig_h]| == 3)
				{
					print fmt("%s is a proxy", c$http$id$orig_h);
				}
			}
		}
		else
		{
			ip[c$http$id$orig_h] = set(value);
		}
	}
}
