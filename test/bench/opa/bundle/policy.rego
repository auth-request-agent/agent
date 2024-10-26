package authz

import future.keywords

default allow_policy := false
default match_policy := false
default allow_default := false
default allow := false

x_source := input.http_request.headers["x-source"]
x_path := input.http_request.headers["x-path"]
x_method := input.http_request.headers["x-method"]

jwt_token := input.http_request.headers["jwt_token"]
jwt_x_source := concat(":", ["jwt", claims.name])

claims := payload {
	io.jwt.verify_hs256(jwt_token, "secret")
	[_, payload, _] := io.jwt.decode(jwt_token)
}
allow_policy if {
	jwt_x_source in ["jwt:client1"]
	x_path in ["/jwt_1/1", "/jwt_1/2", "/jwt_1/3", "/jwt_1/4", "/jwt_1/5", "/jwt_1/6", "/jwt_1/7", "/jwt_1/8", "/jwt_1/9"]
	x_method in ["get"]
}

match_policy if {
	x_path in ["/jwt_1/1", "/jwt_1/2", "/jwt_1/3", "/jwt_1/4", "/jwt_1/5", "/jwt_1/6", "/jwt_1/7", "/jwt_1/8", "/jwt_1/9"]
	x_method in ["get"]
}
allow_policy if {
	jwt_x_source in ["jwt:client1"]
	x_path in ["/jwt_2/1", "/jwt_2/2", "/jwt_2/3", "/jwt_2/4", "/jwt_2/5", "/jwt_2/6", "/jwt_2/7", "/jwt_2/8", "/jwt_2/9"]
	x_method in ["get"]
}

match_policy if {
	x_path in ["/jwt_2/1", "/jwt_2/2", "/jwt_2/3", "/jwt_2/4", "/jwt_2/5", "/jwt_2/6", "/jwt_2/7", "/jwt_2/8", "/jwt_2/9"]
	x_method in ["get"]
}
allow_policy if {
	jwt_x_source in ["jwt:client1"]
	x_path in ["/jwt_3/1", "/jwt_3/2", "/jwt_3/3", "/jwt_3/4", "/jwt_3/5", "/jwt_3/6", "/jwt_3/7", "/jwt_3/8", "/jwt_3/9"]
	x_method in ["get"]
}

match_policy if {
	x_path in ["/jwt_3/1", "/jwt_3/2", "/jwt_3/3", "/jwt_3/4", "/jwt_3/5", "/jwt_3/6", "/jwt_3/7", "/jwt_3/8", "/jwt_3/9"]
	x_method in ["get"]
}
allow_policy if {
	jwt_x_source in ["jwt:client1"]
	x_path in ["/jwt_4/1", "/jwt_4/2", "/jwt_4/3", "/jwt_4/4", "/jwt_4/5", "/jwt_4/6", "/jwt_4/7", "/jwt_4/8", "/jwt_4/9"]
	x_method in ["get"]
}

match_policy if {
	x_path in ["/jwt_4/1", "/jwt_4/2", "/jwt_4/3", "/jwt_4/4", "/jwt_4/5", "/jwt_4/6", "/jwt_4/7", "/jwt_4/8", "/jwt_4/9"]
	x_method in ["get"]
}
allow_policy if {
	jwt_x_source in ["jwt:client1"]
	x_path in ["/jwt_5/1", "/jwt_5/2", "/jwt_5/3", "/jwt_5/4", "/jwt_5/5", "/jwt_5/6", "/jwt_5/7", "/jwt_5/8", "/jwt_5/9"]
	x_method in ["get"]
}

match_policy if {
	x_path in ["/jwt_5/1", "/jwt_5/2", "/jwt_5/3", "/jwt_5/4", "/jwt_5/5", "/jwt_5/6", "/jwt_5/7", "/jwt_5/8", "/jwt_5/9"]
	x_method in ["get"]
}
allow_policy if {
	jwt_x_source in ["jwt:client1"]
	x_path in ["/jwt_6/1", "/jwt_6/2", "/jwt_6/3", "/jwt_6/4", "/jwt_6/5", "/jwt_6/6", "/jwt_6/7", "/jwt_6/8", "/jwt_6/9"]
	x_method in ["get"]
}

match_policy if {
	x_path in ["/jwt_6/1", "/jwt_6/2", "/jwt_6/3", "/jwt_6/4", "/jwt_6/5", "/jwt_6/6", "/jwt_6/7", "/jwt_6/8", "/jwt_6/9"]
	x_method in ["get"]
}
allow_policy if {
	jwt_x_source in ["jwt:client1"]
	x_path in ["/jwt_7/1", "/jwt_7/2", "/jwt_7/3", "/jwt_7/4", "/jwt_7/5", "/jwt_7/6", "/jwt_7/7", "/jwt_7/8", "/jwt_7/9"]
	x_method in ["get"]
}

match_policy if {
	x_path in ["/jwt_7/1", "/jwt_7/2", "/jwt_7/3", "/jwt_7/4", "/jwt_7/5", "/jwt_7/6", "/jwt_7/7", "/jwt_7/8", "/jwt_7/9"]
	x_method in ["get"]
}
allow_policy if {
	jwt_x_source in ["jwt:client1"]
	x_path in ["/jwt_8/1", "/jwt_8/2", "/jwt_8/3", "/jwt_8/4", "/jwt_8/5", "/jwt_8/6", "/jwt_8/7", "/jwt_8/8", "/jwt_8/9"]
	x_method in ["get"]
}

match_policy if {
	x_path in ["/jwt_8/1", "/jwt_8/2", "/jwt_8/3", "/jwt_8/4", "/jwt_8/5", "/jwt_8/6", "/jwt_8/7", "/jwt_8/8", "/jwt_8/9"]
	x_method in ["get"]
}
allow_policy if {
	jwt_x_source in ["jwt:client1"]
	x_path in ["/jwt_9/1", "/jwt_9/2", "/jwt_9/3", "/jwt_9/4", "/jwt_9/5", "/jwt_9/6", "/jwt_9/7", "/jwt_9/8", "/jwt_9/9"]
	x_method in ["get"]
}

match_policy if {
	x_path in ["/jwt_9/1", "/jwt_9/2", "/jwt_9/3", "/jwt_9/4", "/jwt_9/5", "/jwt_9/6", "/jwt_9/7", "/jwt_9/8", "/jwt_9/9"]
	x_method in ["get"]
}
allow_policy if {
	data["team1"][_].name == x_source
	x_path in ["/json_1/1", "/json_1/2", "/json_1/3", "/json_1/4", "/json_1/5", "/json_1/6", "/json_1/7", "/json_1/8", "/json_1/9"]
	x_method in ["get"]
}

match_policy if {
	x_path in ["/json_1/1", "/json_1/2", "/json_1/3", "/json_1/4", "/json_1/5", "/json_1/6", "/json_1/7", "/json_1/8", "/json_1/9"]
	x_method in ["get"]
}
allow_policy if {
	data["team2"][_].name == x_source
	x_path in ["/json_2/1", "/json_2/2", "/json_2/3", "/json_2/4", "/json_2/5", "/json_2/6", "/json_2/7", "/json_2/8", "/json_2/9"]
	x_method in ["get"]
}

match_policy if {
	x_path in ["/json_2/1", "/json_2/2", "/json_2/3", "/json_2/4", "/json_2/5", "/json_2/6", "/json_2/7", "/json_2/8", "/json_2/9"]
	x_method in ["get"]
}
allow_policy if {
	data["team3"][_].name == x_source
	x_path in ["/json_3/1", "/json_3/2", "/json_3/3", "/json_3/4", "/json_3/5", "/json_3/6", "/json_3/7", "/json_3/8", "/json_3/9"]
	x_method in ["get"]
}

match_policy if {
	x_path in ["/json_3/1", "/json_3/2", "/json_3/3", "/json_3/4", "/json_3/5", "/json_3/6", "/json_3/7", "/json_3/8", "/json_3/9"]
	x_method in ["get"]
}
allow_policy if {
	data["team4"][_].name == x_source
	x_path in ["/json_4/1", "/json_4/2", "/json_4/3", "/json_4/4", "/json_4/5", "/json_4/6", "/json_4/7", "/json_4/8", "/json_4/9"]
	x_method in ["get"]
}

match_policy if {
	x_path in ["/json_4/1", "/json_4/2", "/json_4/3", "/json_4/4", "/json_4/5", "/json_4/6", "/json_4/7", "/json_4/8", "/json_4/9"]
	x_method in ["get"]
}
allow_policy if {
	data["team5"][_].name == x_source
	x_path in ["/json_5/1", "/json_5/2", "/json_5/3", "/json_5/4", "/json_5/5", "/json_5/6", "/json_5/7", "/json_5/8", "/json_5/9"]
	x_method in ["get"]
}

match_policy if {
	x_path in ["/json_5/1", "/json_5/2", "/json_5/3", "/json_5/4", "/json_5/5", "/json_5/6", "/json_5/7", "/json_5/8", "/json_5/9"]
	x_method in ["get"]
}
allow_policy if {
	data["team6"][_].name == x_source
	x_path in ["/json_6/1", "/json_6/2", "/json_6/3", "/json_6/4", "/json_6/5", "/json_6/6", "/json_6/7", "/json_6/8", "/json_6/9"]
	x_method in ["get"]
}

match_policy if {
	x_path in ["/json_6/1", "/json_6/2", "/json_6/3", "/json_6/4", "/json_6/5", "/json_6/6", "/json_6/7", "/json_6/8", "/json_6/9"]
	x_method in ["get"]
}
allow_policy if {
	data["team7"][_].name == x_source
	x_path in ["/json_7/1", "/json_7/2", "/json_7/3", "/json_7/4", "/json_7/5", "/json_7/6", "/json_7/7", "/json_7/8", "/json_7/9"]
	x_method in ["get"]
}

match_policy if {
	x_path in ["/json_7/1", "/json_7/2", "/json_7/3", "/json_7/4", "/json_7/5", "/json_7/6", "/json_7/7", "/json_7/8", "/json_7/9"]
	x_method in ["get"]
}
allow_policy if {
	data["team8"][_].name == x_source
	x_path in ["/json_8/1", "/json_8/2", "/json_8/3", "/json_8/4", "/json_8/5", "/json_8/6", "/json_8/7", "/json_8/8", "/json_8/9"]
	x_method in ["get"]
}

match_policy if {
	x_path in ["/json_8/1", "/json_8/2", "/json_8/3", "/json_8/4", "/json_8/5", "/json_8/6", "/json_8/7", "/json_8/8", "/json_8/9"]
	x_method in ["get"]
}
allow_policy if {
	data["team9"][_].name == x_source
	x_path in ["/json_9/1", "/json_9/2", "/json_9/3", "/json_9/4", "/json_9/5", "/json_9/6", "/json_9/7", "/json_9/8", "/json_9/9"]
	x_method in ["get"]
}

match_policy if {
	x_path in ["/json_9/1", "/json_9/2", "/json_9/3", "/json_9/4", "/json_9/5", "/json_9/6", "/json_9/7", "/json_9/8", "/json_9/9"]
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_1/[0-9]+/sub_1/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_1/[0-9]+/sub_1/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_1/[0-9]+/sub_2/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_1/[0-9]+/sub_2/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_1/[0-9]+/sub_3/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_1/[0-9]+/sub_3/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_1/[0-9]+/sub_4/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_1/[0-9]+/sub_4/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_1/[0-9]+/sub_5/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_1/[0-9]+/sub_5/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_1/[0-9]+/sub_6/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_1/[0-9]+/sub_6/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_1/[0-9]+/sub_7/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_1/[0-9]+/sub_7/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_1/[0-9]+/sub_8/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_1/[0-9]+/sub_8/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_1/[0-9]+/sub_9/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_1/[0-9]+/sub_9/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_2/[0-9]+/sub_1/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_2/[0-9]+/sub_1/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_2/[0-9]+/sub_2/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_2/[0-9]+/sub_2/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_2/[0-9]+/sub_3/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_2/[0-9]+/sub_3/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_2/[0-9]+/sub_4/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_2/[0-9]+/sub_4/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_2/[0-9]+/sub_5/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_2/[0-9]+/sub_5/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_2/[0-9]+/sub_6/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_2/[0-9]+/sub_6/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_2/[0-9]+/sub_7/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_2/[0-9]+/sub_7/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_2/[0-9]+/sub_8/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_2/[0-9]+/sub_8/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_2/[0-9]+/sub_9/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_2/[0-9]+/sub_9/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_3/[0-9]+/sub_1/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_3/[0-9]+/sub_1/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_3/[0-9]+/sub_2/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_3/[0-9]+/sub_2/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_3/[0-9]+/sub_3/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_3/[0-9]+/sub_3/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_3/[0-9]+/sub_4/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_3/[0-9]+/sub_4/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_3/[0-9]+/sub_5/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_3/[0-9]+/sub_5/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_3/[0-9]+/sub_6/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_3/[0-9]+/sub_6/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_3/[0-9]+/sub_7/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_3/[0-9]+/sub_7/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_3/[0-9]+/sub_8/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_3/[0-9]+/sub_8/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_3/[0-9]+/sub_9/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_3/[0-9]+/sub_9/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_4/[0-9]+/sub_1/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_4/[0-9]+/sub_1/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_4/[0-9]+/sub_2/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_4/[0-9]+/sub_2/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_4/[0-9]+/sub_3/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_4/[0-9]+/sub_3/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_4/[0-9]+/sub_4/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_4/[0-9]+/sub_4/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_4/[0-9]+/sub_5/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_4/[0-9]+/sub_5/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_4/[0-9]+/sub_6/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_4/[0-9]+/sub_6/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_4/[0-9]+/sub_7/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_4/[0-9]+/sub_7/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_4/[0-9]+/sub_8/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_4/[0-9]+/sub_8/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_4/[0-9]+/sub_9/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_4/[0-9]+/sub_9/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_5/[0-9]+/sub_1/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_5/[0-9]+/sub_1/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_5/[0-9]+/sub_2/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_5/[0-9]+/sub_2/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_5/[0-9]+/sub_3/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_5/[0-9]+/sub_3/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_5/[0-9]+/sub_4/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_5/[0-9]+/sub_4/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_5/[0-9]+/sub_5/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_5/[0-9]+/sub_5/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_5/[0-9]+/sub_6/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_5/[0-9]+/sub_6/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_5/[0-9]+/sub_7/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_5/[0-9]+/sub_7/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_5/[0-9]+/sub_8/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_5/[0-9]+/sub_8/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_5/[0-9]+/sub_9/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_5/[0-9]+/sub_9/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_6/[0-9]+/sub_1/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_6/[0-9]+/sub_1/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_6/[0-9]+/sub_2/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_6/[0-9]+/sub_2/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_6/[0-9]+/sub_3/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_6/[0-9]+/sub_3/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_6/[0-9]+/sub_4/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_6/[0-9]+/sub_4/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_6/[0-9]+/sub_5/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_6/[0-9]+/sub_5/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_6/[0-9]+/sub_6/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_6/[0-9]+/sub_6/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_6/[0-9]+/sub_7/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_6/[0-9]+/sub_7/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_6/[0-9]+/sub_8/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_6/[0-9]+/sub_8/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_6/[0-9]+/sub_9/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_6/[0-9]+/sub_9/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_7/[0-9]+/sub_1/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_7/[0-9]+/sub_1/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_7/[0-9]+/sub_2/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_7/[0-9]+/sub_2/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_7/[0-9]+/sub_3/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_7/[0-9]+/sub_3/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_7/[0-9]+/sub_4/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_7/[0-9]+/sub_4/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_7/[0-9]+/sub_5/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_7/[0-9]+/sub_5/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_7/[0-9]+/sub_6/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_7/[0-9]+/sub_6/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_7/[0-9]+/sub_7/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_7/[0-9]+/sub_7/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_7/[0-9]+/sub_8/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_7/[0-9]+/sub_8/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_7/[0-9]+/sub_9/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_7/[0-9]+/sub_9/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_8/[0-9]+/sub_1/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_8/[0-9]+/sub_1/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_8/[0-9]+/sub_2/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_8/[0-9]+/sub_2/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_8/[0-9]+/sub_3/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_8/[0-9]+/sub_3/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_8/[0-9]+/sub_4/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_8/[0-9]+/sub_4/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_8/[0-9]+/sub_5/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_8/[0-9]+/sub_5/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_8/[0-9]+/sub_6/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_8/[0-9]+/sub_6/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_8/[0-9]+/sub_7/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_8/[0-9]+/sub_7/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_8/[0-9]+/sub_8/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_8/[0-9]+/sub_8/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_8/[0-9]+/sub_9/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_8/[0-9]+/sub_9/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_9/[0-9]+/sub_1/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_9/[0-9]+/sub_1/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_9/[0-9]+/sub_2/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_9/[0-9]+/sub_2/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_9/[0-9]+/sub_3/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_9/[0-9]+/sub_3/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_9/[0-9]+/sub_4/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_9/[0-9]+/sub_4/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_9/[0-9]+/sub_5/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_9/[0-9]+/sub_5/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_9/[0-9]+/sub_6/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_9/[0-9]+/sub_6/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_9/[0-9]+/sub_7/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_9/[0-9]+/sub_7/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_9/[0-9]+/sub_8/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_9/[0-9]+/sub_8/[0-9]+$", x_path)
	x_method in ["get"]
}
allow_policy if {
	x_source in ["client1", "client2", "client2"]
	regex.match("^/regex_9/[0-9]+/sub_9/[0-9]+$", x_path)
	x_method in ["get"]
}

match_policy if {
	regex.match("^/regex_9/[0-9]+/sub_9/[0-9]+$", x_path)
	x_method in ["get"]
}

allow_default if {
	x_source in []
}

allow if {
    allow_policy == true
}

allow if {
    match_policy == false
    allow_default == true
}
