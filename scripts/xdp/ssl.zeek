##! Shunts SSL traffic after connection established.

@load ./main
@load ./shunt-conn-id

event ssl_established(c: connection)
	{
	XDP::Shunt::ConnID::shunt(c);
	}
