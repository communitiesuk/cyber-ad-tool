/* jshint esversion: 6 */
function includeHTML() {
  /* Loop through a collection of all HTML elements: */
  const elements = document.getElementsByTagName("*");
  for (let index = 0; index < elements.length; index++) {
    const element = elements[index];
    /*search for elements with a certain atrribute:*/
    const includedFile = element.getAttribute("w3-include-html");
    if (includedFile) {
      /* Make an HTTP request using the attribute value as the file name: */
      const httpRequest = new XMLHttpRequest();
      httpRequest.onreadystatechange = function () {
        if (this.readyState == 4) {
          if (this.status == 200) {
            element.innerHTML = this.responseText;
          }
          if (this.status == 404) {
            element.innerHTML = "Page not found.";
          }
          /* Remove the attribute, and call this function once more: */
          element.removeAttribute("w3-include-html");
        }
      };
      httpRequest.open("GET", includedFile, true);
      httpRequest.send();
    }
  }
}

function parseDate(date) {
  let parsedDate;
  try {
    const utcSeconds = parseInt((date).substring(6, 19));
    parsedDate = new Date(utcSeconds);
  } catch (error) {
    parsedDate = '';
  }
  return parsedDate;
}

function makeTextFile(text) {
  let textFile = null;
  const data = new Blob([text], {
    type: 'text/plain'
  });
  // "data:text/csv;charset=utf-8," + 
  // If we are replacing a previously generated file we need to
  // manually revoke the object URL to avoid memory leaks.
  if (textFile !== null) {
    window.URL.revokeObjectURL(textFile);
  }
  textFile = window.URL.createObjectURL(data);
  return textFile;
}