$(document).ready(function(){
	//console.log(osis);
});


// $(".edit_mode_trig").click(function(){
// 	$(this).parents(".form_holder").find(".edible_text").removeClass("d-none");
// 	$(this).parents(".form_holder").find(".viewable_text").addClass("d-none");
// 	$(this).siblings(".editback_mode_trig").removeClass("d-none");
// 	$(this).addClass("d-none");
// 	$(this).parents(".form_holder").find(".editable_actionbtn_set").removeClass("invisible");
// });
// $(".editback_mode_trig").click(function(){
// 	$(this).parents(".form_holder").find(".edible_text").addClass("d-none");
// 	$(this).parents(".form_holder").find(".viewable_text").removeClass("d-none");
// 	$(this).siblings(".edit_mode_trig").removeClass("d-none");
// 	$(this).addClass("d-none");
// 	$(this).parents(".form_holder").find(".editable_actionbtn_set").addClass("invisible");
// });
// $(".delete_mode_trig").click(function(){
// 	$(".del_alert_box").removeClass("d-none");
// });
// $(".edel_yes").click(function(){
// 	$(".del_alert_box").addClass("d-none");
// });
// $(".edel_no").click(function(){
// 	$(".del_alert_box").addClass("d-none");
// });

$(".acts_edit").click(function(){
	if($(this).hasClass("acts_link_disabled")){
		//console.log("acts_link_disabled");
		$("#editcheckalert").modal();
	}else{
		//console.log("not_acts_link_disabled");
		$("#editModal").modal();
		
	}
});
$(".acts_delete").click(function(){
	if($(this).hasClass("acts_link_disabled")){
		//console.log("acts_link_disabled");
		$("#deletecheckalert").modal();
	}else{
		//console.log("not_acts_link_disabled");
		$("#deletealert").modal();
		
	}
});


$("body .button-default.xlsx").hide();
$(".act_filter").click(function(){
    $(".filter_box").show();
});
$(".filter_close").click(function(){
    $(".filter_box").hide();
});

$('.the_th_checker[type=checkbox]').change(function() { 
	//console.log('hello') 
	if($(this).is(":checked")){
		//console.log("checked")
		$(".the_checker").prop("checked",true).parents(".the_checker_td").addClass("the_checker_td_actv");
		$(this).parents(".the_checker_th").addClass("the_checker_th_actv");
		checker_length();
	}else if($(this).not(":checked")){
		//console.log("not")
		$(".the_checker").prop("checked",false).parents(".the_checker_td").removeClass("the_checker_td_actv");
		$(this).parents(".the_checker_th").removeClass("the_checker_th_actv");
		checker_length();
	}else{}
});

$("body").on('change','.the_checker',function(){
	checker_length();
	if($(this).is(":checked")){
		$(this).parents(".the_checker_td").addClass("the_checker_td_actv");
	}else if($(this).not(":checked")){
		$(this).parents(".the_checker_td").removeClass("the_checker_td_actv");
	}
});
function checker_length(){
	var the_checker_length=$(".table_master").find(".the_checker:checked").length;
	//console.log(the_checker_length);
	if(the_checker_length=="0"){
		$('.the_th_checker[type=checkbox]').prop("checked",false);
		$(".acts_edit").addClass("acts_link_disabled");
		$(".acts_delete").addClass("acts_link_disabled");
	}else if(the_checker_length=="1"){
		$(".acts_edit").removeClass("acts_link_disabled");
		$(".acts_delete").removeClass("acts_link_disabled");
	}else if(the_checker_length>"1"){
		$(".acts_edit").addClass("acts_link_disabled");
		$(".acts_delete").removeClass("acts_link_disabled");
	}
}

// JavaScript Document
// $(".sbicon").click(function(){// side menu open activity codes
// 	 $(".dash_tabs").toggleClass("dash_tabsshow");
// 	$(".tab_col").toggleClass("tab_col_show");
// 	$(".sbicon").toggleClass("sbiconcls");
// 	$(".dash_cover").toggleClass("dash_cover_show");
// 	// $(".notific_display").fadeOut();
// 	// $(".sidebarcover_ntfc").removeClass("sidebarcovershow");

// });


$(".sbicon").click(function(){// side menu open activity codes
	$(".sidebarin").toggleClass("sidebarinshow");
	$(".sidelinerwhole").toggleClass("sidelinerwholemove");
	$(".sbicon").toggleClass("sbiconcls");
	$(".sidebarcover_sbn").toggleClass("sidebarcovershow");
	$(".notific_display").fadeOut();
	$(".sidebarcover_ntfc").removeClass("sidebarcovershow");
});
$(".sidebarcover_sbn").click(function(){ // side menu close activity codes
	$(".sidebarin").removeClass("sidebarinshow");
	$(".sidelinerwhole").removeClass("sidelinerwholemove");
	$(".sbicon").removeClass("sbiconcls");
	$(".sidebarcover_sbn").removeClass("sidebarcovershow");
	$(".notific_display").fadeOut();
	$(".sidebarcover_ntfc").removeClass("sidebarcovershow");
});

$(".besclistico").click(function(){
    $("html, body").animate({ scrollTop: 0 }, "slow");
});
$(".dash_cover").click(function(){
	$(".dash_tabs").removeClass("dash_tabsshow");
	$(".dash_cover").removeClass("dash_cover_show");
	$(".sbicon").removeClass("sbiconcls");
	$(".tab_col").removeClass("tab_col_show");
});



// $(".fileVal").change(function(e){
// 	var thiVal= $(this).val();		
// 	var ext = thiVal.split('.').pop();	
// 	if(ext=="pdf" || ext=="odt" || ext=="docx"){
// 		$(this).siblings(".showImg").attr('src','../images/ico/file_doc.png');
// 	}else{
// 		$(this).siblings(".showImg").attr('src',URL.createObjectURL(event.target.files[0]));	
// 	}
// 	var fileValue=e.target.files[0].name;
// 	$(this).siblings("span").text(fileValue);
// });

$(".dash_tab_btn").click(function(){
	$(".dash_tab_btn").toggleClass("dash_tab_btnclose");
	$(".dash_tabs").toggleClass("dash_tabsshow");
	$(".dash_tabs_back").toggleClass("dash_tabs_backshow");
});

var count=2;
$("body").on('click','.line_plus',function(){
	if($(".multi_lines_holder").find(".line_field").hasClass("datepicker_multi")){
		$(this).toggleClass("line_plus line_minus").removeClass("line_plus").parents(".lineof_multi").clone("").prependTo(".multi_lines_holder").find(".line_minus").toggleClass("line_minus line_plus").parents(".lineof_multi").find(".datepicker_multi").attr("id","xyg"+count).removeClass("hasDatepicker").val("");
		count++;
		console.log(count);
	}else{
		$(this).toggleClass("line_plus line_minus").removeClass("line_plus").parents(".lineof_multi").clone("").prependTo(".multi_lines_holder").find(".line_minus").toggleClass("line_minus line_plus").parents(".lineof_multi").find(".line_field").val("").focus().parents(".lineof_multi").find(".schedule_box_holder").html("");
	}

});

// $("body").on('click','.line_plus',function(){
// 	var multiplier_factId=$(this).parents(".multi_lines_holder").attr("id");
// 	var htmlContent=g_mad_var1;
// 	$(this).parents(".multi_lines_holder").find(".lineof_multipack").prepend(htmlContent).children(".lineof_multi:first-child").find(".line_field").focus();
// });


// $("body").on('click','.line_minus',function(){
// 	$(this).parents(".lineof_multi").remove();
// });











$("body").on('keyup','.searchInput',function(){

    filterFunction(this);
});

function filterFunction(thisid) {
      var input, filter, ul, li, a, i;
      filter = thisid.value.toUpperCase();
      div = $(thisid).siblings("ul");
      a = $(thisid).siblings("ul").children(".select_li_option");
      if(thisid.value=="") {
        a.removeClass("text-primary d-none");
        a.addClass("d-block");
      }else{
        for (i = 0; i < a.length; i++) {
            txtValue = a[i].textContent || a[i].innerText;
            if (txtValue.toUpperCase().indexOf(filter) > -1) {
              //a[i].classList.add("texto");
              a[i].classList.remove("d-none");
              // a[i].style.display = "";
            } else {
              // a[i].style.display = "none";
              a[i].classList.add("d-none");
              //a[i].classList.remove("texto");
              a[i].classList.remove("d-block");
            }
          }
      }
  }

  $(function(){

        var li = $('.select_ul li'), n = -1, ll = li.length-1;
        $('.selectInput').keypress(function(e){
          var x = e.which;
          li.removeClass('background');
          if(x === 40 || x === 39 || x === 38 || x === 37){
            if(x === 40 || x === 39){
              n++;
              if(n > ll)n = 0;
            }
            else if(x === 38 || x === 37){
              n--;
              if(n < 0)n = ll;
            }
            var ci = li.get(n);
            ci.addClass('background'); $(this).val(ci.text());
          }
        });

    });

  $(document).ready(function(){
    $(".selectOutput").click(function(){
    	$(this).siblings(".selectdropbox").show();
    });
    $(".select_li_option").click(function(){
        select_option_val(this);
    });
    function select_option_val(ar){
        var slo_val=$(ar).html();
        var slo_id=$(ar).attr("id");
        //console.log(slo_id,slo_val);
        $(ar).parents("ul.select_ul").parents(".selectdropbox").siblings(".selectOutput").val(slo_val).prop("id",slo_id).siblings(".selectdropbox").hide();
        $(ar).parents("ul.select_ul").siblings(".searchInput").val("");
        $(ar).parents("ul.select_ul").children(".select_li_option").addClass("d-block");
    }
    // $(".selectInput").focus(function(){
    //     //$(this).siblings("ul").addClass("select_ul")
    // });
    // var lio = $('ul.select_ul > li');
    // var xxx;
    // $(window).on('keyup', function(e){
        
    //     if(e.which === 40){
    //         if(xxx){
    //             xxx.removeClass('bg-primary');
    //             next = xxx.next();
    //             if(next.length > 0){
    //                 xxx = next.addClass('bg-primary');
    //                 select_option_val(xxx);
    //                 console.log(xxx);
    //             }else{
    //                 xxx = lio.eq(0).addClass('bg-primary');
    //                 select_option_val(xxx);
    //             }
    //         }else{
    //             xxx = lio.eq(0).addClass('bg-primary');
    //             select_option_val(xxx);
    //         }
    //     }else if(e.which === 38){
    //         if(xxx){
    //             xxx.removeClass('bg-primary');
    //             next = xxx.prev();
    //             if(next.length > 0){
    //                 xxx = next.addClass('bg-primary');
    //                 select_option_val(xxx);
    //                 console.log(xxx);
    //             }else{

    //                 xxx = lio.last().addClass('bg-primary');
    //                 select_option_val(xxx);
    //             }
    //         }else{

    //             xxx = lio.last().addClass('bg-primary');
    //             select_option_val(xxx);
    //         }
    //     }
    // });

    
  });


$("body").on('change','.custom-file-input',function(e){

	var thiVal= $(this).val();		
	var ext = thiVal.split('.').pop();	
	if(ext=="pdf" || ext=="odt" || ext=="docx"){
		$(this).siblings(".showImg").attr('src','../images/ico/file_doc.png');
	}else{
		$(this).siblings(".showImg").attr('src',URL.createObjectURL(event.target.files[0]));	
	}
	var fileValue=e.target.files[0].name;
	$(this).siblings(".custom-file-label").text(fileValue);
});






