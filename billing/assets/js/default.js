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

$(".user_drop_trig").click(function(){
	$(".user_drop_response").toggleClass("user_drop_active");
	
});
$(document).click(function (e) {
    if (!$(e.target).parents().addBack().is('.user_drop_trig')) {
        $(".user_drop_response").removeClass("user_drop_active");
    }
});
$(".user_drop_response").click(function (e) {
    e.stopPropagation();
});


$(".page_info_trig").click(function(){
	$(".page_info_response").toggleClass("page_infoactive");

});
$(document).click(function (e) {
    if (!$(e.target).parents().is('.page_info_trig')) {
        $(".page_info_response").removeClass("page_infoactive");
    }
});
$(".page_info_response").click(function (e) {
    e.stopPropagation();
});

$(document).ready(function(){
	var pageinfo=$(".page_tutorial").html();
	//console.log(pageinfo);
	$(".page_infoin").html(pageinfo);
});




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
// $(document).click(function (e) {
//     if (!$(e.target).parents().addBack().is('.act_filter')) {
//         $(".filter_box").hide();
//     }
// });
// $(".filter_box").click(function (e) {
//     e.stopPropagation();
// });



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
	$(".superadmin_sidebarin").removeClass("sasidebarinshow");
	$(".sidelinerwhole").toggleClass("sidelinerwholemove");
	$(".sbicon").toggleClass("sbiconcls");
	$(".sidebarcover_sbn").toggleClass("sidebarcovershow");
	$(".superadmin_sidebarcover").removeClass("sidebarcovershow");
	$(".notific_display").fadeOut();
	$(".sidebarcover_ntfc").removeClass("sidebarcovershow");
});
$(".sidebarcover_sbn").click(function(){ // side menu close activity codes
	$(".superadmin_sidebarin").removeClass("sasidebarinshow");
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


// $(".supadmin").click(function(){
// 	$(".superadmin_sidebarin").toggleClass("sasidebarinshow");
// 	$(".sidebarin").removeClass("sidebarinshow");
// 	$(".sidelinerwhole").removeClass("sidelinerwholemove");
// 	$(".sbicon").removeClass("sbiconcls");
// 	$(".superadmin_sidebarcover").toggleClass("sidebarcovershow");
// 	$(".sidebarcover_sbn").removeClass("sidebarcovershow");
// 	$(".notific_display").fadeOut();
// 	$(".sidebarcover_ntfc").removeClass("sidebarcovershow");
	
// });
// $(".superadmin_sidebarcover").click(function(){ // side menu close activity codes
// 	$(".superadmin_sidebarin").removeClass("sasidebarinshow");
// 	$(".superadmin_sidebarcover").removeClass("sidebarcovershow");
// });


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

// var count=2;
// $("body").on('click','.line_plus',function(){
// 	if($(".multi_lines_holder").find(".line_field").hasClass("datepicker_multi")){
// 		$(this).toggleClass("line_plus line_minus").removeClass("line_plus").parents(".lineof_multi").clone("").prependTo(".multi_lines_holder").find(".line_minus").toggleClass("line_minus line_plus").parents(".lineof_multi").find(".datepicker_multi").attr("id","xyg"+count).removeClass("hasDatepicker").val("");
// 		count++;
// 		console.log(count);
// 	}else{
// 		$(this).toggleClass("line_plus line_minus").removeClass("line_plus").parents(".lineof_multi").clone("").prependTo(".multi_lines_holder").find(".line_minus").toggleClass("line_minus line_plus").parents(".lineof_multi").find(".line_field").val("").focus().parents(".lineof_multi").find(".schedule_box_holder").html("");
// 	}

// });
$("body").on('click','.line_minus',function(){
	$(this).parents(".lineof_multi").remove();
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


// menu system
// $(".sidemenulist li").mouseenter(function(){
//   $(this).children(".submenu_1").addClass("submenu_1active");
// });
// $(".sidemenulist li").mouseleave(function(){
//   $(this).children(".submenu_1").removeClass("submenu_1active");
// });
// $(".sidemenulist li > .submenu_1 > ul > li").mouseenter(function(){
//   $(this).children(".submenu_2").addClass("submenu_2active");

// });
// $(".sidemenulist li > .submenu_1 > ul > li").mouseleave(function(){
//   $(this).children(".submenu_2").removeClass("submenu_2active");
// });


// $(".sidemenulist li > .submenu_1 > ul > li > .submenu_2 > ul > li").hover(function(){
//   $(this).children(".submenu_3").toggleClass("submenu_3active");
// });

// $(".sidemenulist li > .submenu_1 > ul > li > .submenu_2 > ul > li > .submenu_3 > ul > li").hover(function(){
//   $(this).children(".submenu_4").toggleClass("submenu_4active");
// });
// menu system


// tooltip for table content
$("body").on('mouseenter','.tbcell_long',function(){
	var tooler_text=$(this).html();
	var tooler="<div class='tooler'><div class='toolerin'>"+tooler_text+"</div></div>";
	var tbcell_offset=$(this).offset();
	var body_height=$(window).height();
	console.log(tbcell_offset.left, tbcell_offset.top);
	$("body").append(tooler).children(".tooler").css({ bottom: body_height-tbcell_offset.top, left: tbcell_offset.left });
});
$("body").on('mouseout','.tbcell_long',function(){
	$('.tooler').remove();
});
// tooltip for table content



$(document).ready(function() {
  $(document).on('focus', ':input', function() {
    $(this).attr('autocomplete', 'off');
  });
});


