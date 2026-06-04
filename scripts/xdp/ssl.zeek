##! Shunts SSL traffic after connection established.

@load ./main
@load ./shunt-conn-id

module XDP::Shunt::SSL;

redef enum XDP::Shunt::ConnID::ShuntTrigger += { SSL };

event ssl_established(c: connection)
	{
	XDP::Shunt::ConnID::shunt(c, SSL);
	}
