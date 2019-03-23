function findContact() {
  // Declare variables
  var input, filter, table, tr, td, i, txtValue;
  input = document.getElementById("mysearchBox");
  filter = input.value.toUpperCase();
  table = document.getElementById("mycontactTable");
  tr = table.getElementsByTagName("tr");

  // Loop through all table rows, and hide those who don't match the search query
  for (i = 0; i < tr.length; i++) {
        tds_in_row = tr[i].getElementsByTagName("td");
        td_name = tds_in_row[0];
        td_surname = tds_in_row[1];

        if (td_name || td_surname) {
          txtValue_name = td_name.textContent || td_name.innerText;
          txtValue_surname = td_surname.textContent || td_surname.innerText;

          if (txtValue_name.toUpperCase().indexOf(filter) > -1 || txtValue_surname.toUpperCase().indexOf(filter) > -1) {
            tr[i].style.display = "";
          } else {
            tr[i].style.display = "none";
          }
        }
  }
}
