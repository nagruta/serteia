%%
%%  Copyright © 2025 Christopher Augustus
%%
%%  This Source Code Form is subject to the terms of the Mozilla Public
%%  License, v. 2.0. If a copy of the MPL was not distributed with this
%%  file, You can obtain one at http://mozilla.org/MPL/2.0/.
%%
-module(serinets).
-export([acquire/0, create/1, init/1, start/2, do/1]).

-record(mod,{ % copied from otp/lib/inets/include/httpd.hrl
  init_data,
  data=[],
  socket_type=ip_comm,
  socket,
  config_db,
  method,
  absolute_uri=[],
  request_uri,
  http_version,
  request_line,
  parsed_header=[],
  entity_body,
  connection}).

-define(NAME_SINGLETON    , list_to_atom(?MODULE_STRING++"_single")).
-define(HTTPD_ADDR_LOCAL  , "localhost"                 ).
-define(HTTPD_PORT_LOCAL  , 8088                        ).
-define(HTTPD_PORT_PUBLIC , 4433                        ).
-define(PATH_MODULE       , filename:dirname(proplists:get_value(source, module_info(compile)))).
-define(PATH_CODE         , ?PATH_MODULE++"/.."         ).
-define(PATH_TOP          , ?PATH_CODE++"/.."           ).
-define(DIR_LOG           , "log"                       ).
-define(PATH_LOG          , ?PATH_TOP++"/"++?DIR_LOG    ).
-define(PATH_CERT         , ?PATH_TOP++"/cert"          ).
-define(FILE_CERT         , ?PATH_CERT++"/fullchain.pem").
-define(FILE_KEY          , ?PATH_CERT++"/privkey.pem"  ).
-define(PATH_SITE         , ?PATH_TOP++"/site"          ).

acquire() ->
  case whereis(?NAME_SINGLETON) of
    Pid when is_pid(Pid) -> Pid;
    _ -> create(local)
  end.

create(Addr) ->
  case whereis(?NAME_SINGLETON) of
    Pid when is_pid(Pid) -> {error,already_exists_at_pid,Pid};
    _ -> spawn(?MODULE, init, [Addr])
  end.

init(Addr) ->
  case Addr of
    local -> start(?HTTPD_ADDR_LOCAL, ?HTTPD_PORT_LOCAL );
    _     -> start(Addr             , ?HTTPD_PORT_PUBLIC)
  end.

start(Addr, Port) ->
  case file:make_dir(?PATH_LOG) of
    ok -> report("Made directory "++?PATH_LOG), ok;
    {error,eexist} -> ok;
    Bad -> ok = Bad
  end,
  case {file:read_file_info(?FILE_CERT),
        file:read_file_info(?FILE_KEY )} of
    {{ok,_},{ok,_}} -> %% support HTTPS
      ok = application:ensure_started(asn1),
      ok = application:ensure_started(crypto),
      ok = application:ensure_started(public_key),
      ok = application:ensure_started(ssl),
      SocketType = {socket_type,
        {ssl,[{certfile,?FILE_CERT},{keyfile,?FILE_KEY}]}};
    _ -> SocketType = {ip_comm},
        report("No HTTPS; missing cert files")
  end,
  ok = application:ensure_started(inets),
  {ok,PidHttpd} = inets:start(httpd, [
     {bind_address    , Addr                          }
    ,{document_root   , ?PATH_SITE                    }
    ,{port            , Port                          }
    ,{server_name     , Addr                          }
    ,{server_root     , ?PATH_TOP                     }
    ,SocketType
    ,{modules         , [serinets, mod_alias, mod_get, mod_log] }
    %% mod_alias config:
    ,{directory_index , ["serteia.org/index.html"]    }
    %% mod_log config:
    ,{error_log       , ?DIR_LOG++"/error.log"        }
    ,{security_log    , ?DIR_LOG++"/security.log"     }
    ,{transfer_log    , ?DIR_LOG++"/transfer.log"     }
  ]),
  register(?NAME_SINGLETON, self()),
  receive
    stop        -> inets:stop(httpd, PidHttpd), ok;
    stop_inets  -> inets:stop(), ok
  end.

do(Info) ->
  report(Info#mod.absolute_uri),
  {proceed,Info#mod.data}.

report(Info) ->
  %% TODO: ### ALSO OUTPUT TO LOG FILE
  io:fwrite(Info++".\n").
