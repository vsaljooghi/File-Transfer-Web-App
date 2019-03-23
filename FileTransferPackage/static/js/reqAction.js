$(document).on("click", ".reqAction", function () {
     var myReqID = $(this).data('req_id');
     var myReqAction = $(this).data('req_action');

     $('#reviewerCommentContinue').click(function() {
                                        var myReviewerCommentTxt = $('#reviewerCommentTxt').val();
                                        $.getJSON($SCRIPT_ROOT + '/ajax/revComment', {req_id: myReqID, revComment: myReviewerCommentTxt});
                                        $('#reviewerCommentModal').modal('hide');
                                        window.location.replace("/req_actions/" + myReqAction + "?req_id=" + myReqID);
                                       });
});
