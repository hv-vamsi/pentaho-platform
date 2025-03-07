/*! ******************************************************************************
 *
 * Pentaho
 *
 * Copyright (C) 2024 by Hitachi Vantara, LLC : http://www.pentaho.com
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file.
 *
 * Change Date: 2029-07-20
 ******************************************************************************/


var docHead = document.getElementsByTagName("head")[0];

(function() {

if(window.location.href.indexOf("theme=") > -1){
  var startIdx = window.location.href.indexOf("theme=")+("theme=".length);
  var endIdx = window.location.href.indexOf("&", startIdx) > -1 ? window.location.href.indexOf("&", startIdx) : window.location.href.length;
  active_theme = window.location.href.substring(startIdx, endIdx);
}

var originalOnLoad = window.onload;
window.onload = function () {
  if (originalOnLoad) {
    originalOnLoad();
  }
  customizeThemeStyling();
}

if(window.core_theme_tree){
  includeResources(core_theme_tree, true);
}

if(window.module_theme_tree){
  includeResources(module_theme_tree, false);
}

function addStylesheet(url) {
    var link = document.createElement('link');
    link.rel = 'stylesheet';
    link.type = 'text/css';
    link.href = url + (document.all ? ("?ts=" + (new Date().getTime())) : "");
    document.getElementsByTagName('head')[0].appendChild(link);
}

function addScript(url) {
    var script = document.createElement('script');
    script.type = "text/javascript";
    script.src = url;
    document.getElementsByTagName('head')[0].appendChild(script);
}

function includeResources(resourceTree, isCore) {
  var activeTheme = resourceTree && resourceTree[active_theme];
  if(!activeTheme) { return; }

  if(isCore && activeTheme.responsive) {
    document.documentElement.classList.add("responsive-theme");
  }

  var cssPat = /\.css$/;
  var resources = activeTheme.resources;
  for(var i = 0; i < resources.length; i++){
    var baseName = resources[i];
    var basePath = CONTEXT_PATH + activeTheme.rootDir;
    if(cssPat.test(baseName)){
      addStylesheet(basePath + baseName);

      // Check to see if we're in a mobile device, if so add a "-mobile"
      if(navigator.userAgent.match(/(iPad|iPod|iPhone)/) != null){
        addStylesheet(basePath + baseName.replace('.css', '') + '-mobile.css');
      }
    } else {
      addScript(basePath + baseName);
    }
  }
}

}());

function customizeThemeStyling() {
  // if it is IE, inject an IE class to the body tag to allow for custom IE css by --> .IE .myclass {}
  var className = "",
      regEx = null,
      isIE = false,
      version = 0;

  // updated due to user agent string changes on IE11
  // source: http://msdn.microsoft.com/en-us/library/ie/bg182625.aspx#uaString
  if (navigator.appName == 'Microsoft Internet Explorer') {
    regEx = new RegExp("MSIE ([0-9]{1,})[\.0-9]{0,}");
    isIE = true;
  } else if (navigator.appName == 'Netscape') {
    regEx = new RegExp("Trident/.*rv:([0-9]{1,}[\.0-9]{0,})");
  }

  if (regEx != null) {
    if (regEx.exec(navigator.userAgent) != null) {
      version = parseInt( RegExp.$1 );
      className += " IE" + version;
      isIE = true;
    }
  }

  if (isIE) {
    // class used to open all pdfs in another window due to z-index issues with pdf readers in IE browsers
    document.getElementsByTagName("body")[0].className += " pdfReaderEmbeded";

    // the IE classes are not being added to IE11 due to all the dojo upgrade tests where made against
    // IE11 without these classes. If is safer for now to keep the class not added
    if (version <= 11) {
      document.getElementsByTagName("body")[0].className += className;
    }
  } else {
    const isSafari = /^((?!chrome|android).)*safari/i.test(navigator.userAgent);
    if (isSafari) {
      document.documentElement.classList.add("safari");
    }
  }
}
