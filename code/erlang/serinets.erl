-export([main/1]).

main(_) ->
  ok = inets:start(),
  {ok, _} = inets:start(httpd, [
    {server_name,   "serteia"   },
    {server_root,   "."         },
    {document_root, "."         },
    {bind_address,  "localhost" },
    {port,          8088        }
  ]),
  receive
    stop -> ok
  end.
