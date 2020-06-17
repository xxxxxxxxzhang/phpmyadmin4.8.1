##! File Upload attack detection.

@load base/protocols/http/main.zeek
@load base/protocols/http/utils.zeek
@load base/protocols/http


module HTTP;
export {
    ## Describes the type of notice we will generate with the Notice framework.
    ## Notices allow Zeek to generate some kind of extra notification beyond its default log types.
    redef enum Notice::Type += {
		    File_Include_Attack,
    };
	

}



event file_state_remove(f: fa_file)
	{
   if ("GET" == f$http$method && "../../../../" in f$http$uri)
          {
        
                local n: Notice::Info = Notice::Info($note=File_Include_Attack, 
                                                 $msg="file include", 
                                                 $f=f);
                                                     
                NOTICE(n);
                print(f$http$uri);
        
          }
  }