%%
%%  Copyright © 2025 Christopher Augustus
%%
%%  This Source Code Form is subject to the terms of the Mozilla Public
%%  License, v. 2.0. If a copy of the MPL was not distributed with this
%%  file, You can obtain one at http://mozilla.org/MPL/2.0/.
%%
-module(serinets).
-export([acquire/0, create/1, init/1, do/1]).

-include_lib("kernel/include/file.hrl").
-include_lib("inets/include/httpd.hrl").
%%-record(mod,
%%  init_data,
%%  data=[],
%%  socket_type=ip_comm,
%%  socket,
%%  config_db,
%%  method,
%%  absolute_uri=[],
%%  request_uri,
%%  http_version,
%%  request_line,
%%  parsed_header=[],
%%  entity_body,
%%  connection}).

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
-define(PATH_SITE_HERE    , ?PATH_TOP++"/site"          ).
-define(PATH_SITE_THERE   , ?PATH_TOP++"/../site"       ).

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
    local -> p_start(?HTTPD_ADDR_LOCAL, ?HTTPD_PORT_LOCAL );
    _     -> p_start(Addr             , ?HTTPD_PORT_PUBLIC)
  end.

p_start(Addr, Port) ->
  p_report("starting this process "++pid_to_list(self())),
  Sites = lists:append(p_subdirs(?PATH_SITE_HERE),
                       p_subdirs(?PATH_SITE_THERE)),
  ets:new(   ?MODULE, [duplicate_bag, named_table]),
  ets:insert(?MODULE, {serteia_sites, Sites}),
  lists:foreach(fun (Site) ->
      Domain = element(1, Site),
      Path   = element(2, Site),
      ets:insert(?MODULE, {alias, {"/"++Domain++"/", Path++"/"}}),
      p_report("site "++Domain++": "++Path)
    end, Sites),
  case file:make_dir(?PATH_LOG) of
    ok -> p_report("Made directory "++?PATH_LOG), ok;
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
        p_report("No HTTPS support; missing cert files")
  end,
  ok = application:ensure_started(inets),
  {ok,PidHttpd} = inets:start(httpd, [
     {bind_address    , Addr                        }
    ,{document_root   , ?PATH_SITE_HERE             }
    ,{port            , Port                        }
    ,{server_name     , Addr                        }
    ,{server_root     , ?PATH_TOP                   }
    ,SocketType
    ,{modules         , [serinets, mod_get, mod_log]}
    %% mod_log config:
    ,{error_log       , ?DIR_LOG++"/error.log"      }
    ,{security_log    , ?DIR_LOG++"/security.log"   }
    ,{transfer_log    , ?DIR_LOG++"/transfer.log"   }
  ]),
  p_report("started inets httpd process "++pid_to_list(PidHttpd)),
  register(?NAME_SINGLETON, self()),
  p_loop(PidHttpd, Addr, Port).

p_loop(PidHttpd, Addr, Port) ->
  receive
    {report,Info} -> p_report(Info),    p_loop(PidHttpd, Addr, Port);
    restart       -> p_stop(PidHttpd),  p_start(Addr, Port);
    stop          -> p_stop(PidHttpd),  ok;
    stop_inets    -> inets:stop(),      ok
  end.

p_stop(PidHttpd) ->
  unregister(?NAME_SINGLETON),
  inets:stop(httpd, PidHttpd),
  ets:delete(?MODULE).

do(Info) ->
  Domain = lists:takewhile( % before port or first /
    fun(C) -> (C =/= $:) and (C =/= $/) end, Info#mod.absolute_uri),
  DomUri = "/"++Domain++Info#mod.request_uri,
  ReqUri = case lists:last(DomUri) of
             $/ -> DomUri++"index.html";
             _  -> DomUri
           end,
  %%p_do_report(ReqUri),
  % !!! we must call mod_alias directly to pass our modified ReqUri
  Response = mod_alias:do(
    #mod{config_db   = ?MODULE,
         request_uri = ReqUri,
         data        = Info#mod.data}),
  Data = element(2, Response),
  %%p_do_report(Data),
  %%Path = mod_alias:path(
  %%  Data, Info#mod.config_db, Info#mod.request_uri),
  %%p_do_report(Path),
  %%p_do_report(ReqUri++" -> "++Path),
  {proceed,Data}.

p_do_report(Info) ->
  case whereis(?NAME_SINGLETON) of
    % writing to standard out does not show from the httpd calling process
    Pid when is_pid(Pid) -> Pid ! {report,Info};
    _ -> p_report(Info)
  end.

p_report(Info) ->
  %% TODO: ### ALSO OUTPUT TO LOG FILE
  io:fwrite("~s: ~p~n", [?NAME_SINGLETON, Info]).

p_subdirs(Path) ->
  case file:list_dir(Path) of
    {ok,Filenames} -> lists:filtermap(
      fun(Filename) ->
        Filepath = Path++"/"++Filename,
        case file:read_file_info(Filepath) of
          {ok,FileInfo} ->
            case FileInfo#file_info.type =:= directory of
              true  -> {true, {Filename, Filepath}};
              false -> false
            end;
          _ -> false
        end
      end,
      Filenames);
    _ -> []
  end.
