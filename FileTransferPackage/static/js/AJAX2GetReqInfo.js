  $(function() {
    $('a.Req_Info').bind('click', function() {
        
      $.getJSON($SCRIPT_ROOT + '/ajax/user_req_info', {req_id: $(this).attr("id")}, 
        function(data) {
          $("#req_desc").text(data.desc);
          $("#req_recip").text(data.recip);
          $("#req_date").text(data.req_date);
          $("#rev_date").text(data.review_date);
          $("#rev_comment").text(data.rev_comment);
        }
      );
      
      return false;
    });
  });
