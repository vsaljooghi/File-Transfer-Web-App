$(document).on("click", ".delUser_Dialog", function () {
     var myUserID = $(this).data('user_id');
     $(".modal-footer form").attr("action", "/delete_account/" + myUserID);
});
