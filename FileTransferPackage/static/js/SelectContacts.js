 $(function(){
   $('#Select_Contacts').bind('click', function(){
        var recipients_textarea = $('textarea#recipients').val();
        $.each($("input[name='contact_check']"), function(){$(this).prop('checked', false);}); // Uncheck all the contacts
        var selected_emails = recipients_textarea.match(/([a-zA-Z0-9._+-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+)/gi);
        
        if(selected_emails != null){
            for(var i=0; i<selected_emails.length; i++) {
                
                var rowIndex = $("td").filter(function() {
                                                return $(this).text() == selected_emails[i];
                                              }).closest("tr").index();
                
                $('table tr').eq(rowIndex).find('td').eq(4).find('input').prop('checked', true);                
            }
        }
   });
 });
        
