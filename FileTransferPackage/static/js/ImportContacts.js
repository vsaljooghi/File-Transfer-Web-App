  $(function() {
    $('#Import_Contacts').bind('click', function(){
        var myrecipients=""
        
        $.each($("input[name='contact_check']:checked"), function(){
                                                           var rowIndex = $(this).closest('tr').index();
                                                           var name = $('table tr').eq(rowIndex).find('td').eq(0).text();
                                                           var surname = $('table tr').eq(rowIndex).find('td').eq(1).text();                                                          
                                                           var email = $('table tr').eq(rowIndex).find('td').eq(3).text();                                                          
                                                           var mycontact = name+","+surname+"<"+email+">; "
                                                           myrecipients +=mycontact;
                                                         }
        );
        
        $("#recipients").val(myrecipients);
        
        $('#ContactModal').modal('hide');
        return false;
    });
  });
