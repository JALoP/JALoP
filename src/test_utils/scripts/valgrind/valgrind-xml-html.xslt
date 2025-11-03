<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
	<xsl:output indent="yes" method="html" encoding="UTF-8"/>
	<xsl:template match="/">
		<html lang="en">
            <style>
				#error_table{border: 1px; width: 100%; cellspacing:0; border-spacing:0; border-collapse:collapse; display: block}
				#frame_table{border: 1px; width: 100%; cellspacing:0; border-spacing:0; border-collapse:collapse; display: block}
				#frame_table th{color: black; text-decoration: none;border: solid 1px; padding:5px; margin:0}
				#frame_table td {border: solid 1px; padding: 5px; margin:0}
				#error_table th{color: black; text-decoration: none;border: solid 1px; padding:5px; margin:0}
				#error_table td {border: solid 1px; padding: 5px; margin:0}
				#main_div {position: absolute; left:0%; top:0%; width:100%; height:100%; display: block}
				#top_div  {position: absolute; left:1%; top:1%; width:98%; height:10%; display: block; border: 1px solid black; background: white;}
				#left_div {position: absolute; left:1%; top:11%; width:30%;  height: 88%; border:1px solid #4169e1; display: block; overflow:auto }
				#right_div{position: absolute; left:32%; top:11%; width:66%; height: 88%; border:1px solid #4169e1; display: block; overflow:auto}
				.frame_row {display:none}
				.error_row:hover {background-color: #4169e1}
				#error_table th:hover {background-color: #4169e1}
				caption{font-size: 1em; margin: 10px; font-weight: bold; color:#4169e1}
				#summary_table{margin-left:20px;border: 1px; width: 100%; display: block; text-align:center; border-collapse:collapse;}
				#summary_table th{color: black; text-decoration: none;border: solid 1px; padding:5px; margin:0}
				#summary_table td {border: solid 1px; padding: 5px; margin:0; background:white; color: #4169e1}
				#summary_table tr {width: 100%}
				h4 {margin-left: 20px; padding: 5px; margin: 5px; color: #4169e1}
            </style>
            <script type="text/javascript">
				<xsl:text disable-output-escaping="yes">
					<![CDATA[
						function clear_frame_rows(){
							const els = document.getElementsByClassName('frame_row');
							for(let x=0; x<els.length; x++){
								els[x].style.display = 'none';
							}
						}
						function show_all_frame_rows(){
							const els = document.getElementsByClassName('frame_row');
							for(let x=0; x<els.length; x++){
								els[x].style.display = 'table-row';
							}
						}
						//Stack Frame Table
						function show_frame_row(frame_row_id, message){
							clear_frame_rows();
							els = document.getElementsByClassName(frame_row_id);
							for(let x=0; x<els.length; x++){
								els[x].style.display = 'table-row';
							}
							caption = document.getElementById("frame_table_caption");
							caption.innerHTML = "Stack Frame Table - " + message;
						}
						var SyscallParam = 0;
						var Leak_StillReachable = 0;
						var Leak_PossiblyLost = 0;
						var Leak_IndirectlyLost = 0;
						var Leak_DefinitelyLost = 0;
						var InvalidWrite = 0;
						var InvalidRead = 0;
						var TotalErrors = 0;
						function hexToDec(){
							table = document.getElementById("error_table");
							rows = table.rows;
							var hex;
							var cell;
							var error;
							for (var x=1; x<rows.length; x++){
								cell = rows[x].getElementsByTagName("td")[0];
								hex = parseInt(cell.innerHTML);
								cell.innerHTML = hex;

								error = rows[x].getElementsByTagName("td")[2].innerHTML;
								TotalErrors++;
								if(error === "InvalidWrite"){InvalidWrite++;}
								if(error === "InvalidRead"){InvalidRead++;}
								if(error === "Leak_StillReachable"){Leak_StillReachable++;}
								if(error === "Leak_PossiblyLost"){Leak_PossiblyLost++;}
								if(error === "Leak_IndirectlyLost"){Leak_IndirectlyLost++;}
								if(error === "Leak_DefinitelyLost"){Leak_DefinitelyLost++;}
								if(error === "SyscallParam"){SyscallParam++;}
							}
							
							te = document.getElementById("total_errors");
							te.innerHTML = TotalErrors;
							te = document.getElementById("InvalidWrite");
							te.innerHTML = InvalidWrite;
							te = document.getElementById("InvalidRead");
							te.innerHTML = InvalidRead;
							te = document.getElementById("Leak_StillReachable");
							te.innerHTML = Leak_StillReachable;
							te = document.getElementById("Leak_PossiblyLost");
							te.innerHTML = Leak_PossiblyLost;
							te = document.getElementById("Leak_IndirectlyLost");
							te.innerHTML = Leak_IndirectlyLost;
							te = document.getElementById("Leak_DefinitelyLost");
							te.innerHTML = Leak_DefinitelyLost;
							te = document.getElementById("SyscallParam");
							te.innerHTML = SyscallParam;
							
							table = document.getElementById("frame_table");
							rows = table.rows;
							var hex;
							var cell;
							for (var x=1; x<rows.length; x++){
								cell = rows[x].getElementsByTagName("td")[0];
								hex = parseInt(cell.innerHTML);
								cell.innerHTML = hex;
							}
						}
						var start_position = 0;
						var end_position = 100;
						function sortTable(table_name,column, isNumeric){
							var table, rows, switching, i, x, y, shouldSwitch;
							table = document.getElementById(table_name);
							switching = true;
							while(switching){
								switching = false;
								rows = table.rows;
								count = 0;
								for(i=1; i<(rows.length-1); i++){
									shouldSwitch = false;
                                    if(isNumeric){
                                        x = parseInt(rows[i].getElementsByTagName("td")[column].innerHTML);
                                        y = parseInt(rows[i+1].getElementsByTagName("td")[column].innerHTML);
                                    }
                                    else{
                                        x = rows[i].getElementsByTagName("td")[column].innerHTML;
                                        y = rows[i+1].getElementsByTagName("td")[column].innerHTML;
                                    }
									if(x > y){
										shouldSwitch = true;
										break;
									}
								}
								if(shouldSwitch){
									rows[i].parentNode.insertBefore(rows[i+1], rows[i]);
									switching = true;
								}
							}
						}
                    ]]>
				</xsl:text>
			</script>
			<body onload="hexToDec()">
            
			<div id="main_div">
			<div id="top_div">
					<h4>Valgrind <xsl:value-of select="valgrindoutput/preamble/line[4]"/></h4>
				<table id="summary_table">
					<tr>
						<td>Total Errors</td>
						<td id="total_errors"/>
						<td>InvalidWrite</td>
						<td id="InvalidWrite"/>
						<td>InvalidRead</td>
						<td id="InvalidRead"/>
						<td>Leak_StillReachable</td>
						<td id="Leak_StillReachable"/>
						<td>Leak_PossiblyLost</td>
						<td id="Leak_PossiblyLost"/>
						<td>Leak_IndirectlyLost</td>
						<td id="Leak_IndirectlyLost"/>
						<td>Leak_DefinitelyLost</td>
						<td id="Leak_DefinitelyLost"/>
						<td>SyscallParam</td>
						<td id="SyscallParam"/>
						
					</tr>
				</table>
			</div>
			<div id="left_div">
            <table id="error_table" style="display: block" width="100%">
				<caption>Error Table</caption>
                <tr>
                    <th onclick="sortTable('error_table', 0, 1)">ct</th>
					<th>ID</th>
                    <th onclick="sortTable('error_table', 2, 0)">kind</th>
                    <th onclick="sortTable('error_table', 3, 1)">leakedbytes</th>
                    <th onclick="sortTable('error_table', 4, 1)">leakedblocks</th>
                </tr>
            	<xsl:for-each select="valgrindoutput/error">
                <tr>
					<xsl:variable name="caption">
						<xsl:value-of select="./unique"/>
						<xsl:text> </xsl:text> 
						<xsl:value-of select="./kind"/>
						<xsl:text> </xsl:text>
						<xsl:value-of select="./xwhat/leakedbytes"/>
						<xsl:text> </xsl:text>
						<xsl:value-of select="./xwhat/leakedblocks"/>
					</xsl:variable>
					<xsl:attribute name="class">error_row</xsl:attribute>
					<xsl:attribute name="onclick">show_frame_row('<xsl:value-of select="./unique"/>_frame_row', '<xsl:value-of select="$caption"/>' )</xsl:attribute>
                    <td><xsl:value-of select="./unique"/></td>
					<td><xsl:value-of select="./unique"/></td>
                    <td><xsl:value-of select="./kind"/></td>
                    <td><xsl:value-of select="./xwhat/leakedbytes"/></td>
                    <td><xsl:value-of select="./xwhat/leakedblocks"/></td>
                </tr>
            	</xsl:for-each> 
            </table> 
			</div>
			<div id="right_div">
			<table id="frame_table">
				<caption id="frame_table_caption">Stack Frame Table</caption>
				<thead>
                <tr>					
                    <th style="width: 5%;">ct</th>
					<th style="width: 5%;">ID</th>
                    <th style="width: 10%;">ip</th>
                    <th style="width: 20%;">obj</th>
                    <th style="width: 20%;">dir</th>
					<th style="width: 20%;">file</th>
					<th style="width: 5%;">line</th>
                    <th>fn</th>
                </tr>
				</thead>
				<tbody>
            	<xsl:for-each select="valgrindoutput/error">
				<xsl:for-each select="./stack/frame">
                <tr>
					<xsl:attribute name="class">frame_row <xsl:value-of select="../../unique"/>_frame_row</xsl:attribute>
                    <td><xsl:value-of select="../../unique"/></td>
					<td><xsl:value-of select="../../unique"/></td>
					<td><xsl:value-of select="./ip"/></td>
					<td><xsl:value-of select="./obj"/></td>
					<td><xsl:value-of select="./dir"/></td>
					<td><xsl:value-of select="./file"/></td>
					<td><xsl:value-of select="./line"/></td>
					<td><xsl:value-of select="./fn"/></td>			
                </tr>
				</xsl:for-each>
            	</xsl:for-each> 
				</tbody>
            </table>
			</div>
			</div>
			</body>   
        </html>
    </xsl:template>
</xsl:stylesheet>

<!-- xsltproc src/test_utils/scripts/valgrind/valgrind-xml-html.xslt test_logs/valgrind/valgrind-rust-filter.xml  -->