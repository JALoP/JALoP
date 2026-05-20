<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
	<xsl:output indent="yes" method="html" encoding="UTF-8"/>
	<xsl:template match="/">
		<html lang="en">
            <style>
				#summary_table{border: 1px; width: 100%; cellspacing:0; border-spacing:0; border-collapse:collapse; display: block}
				#summary_table th{color: black; text-decoration: none;border: solid 1px; padding:5px; margin:0}
				#summary_table td {border: solid 1px; padding: 5px; margin:0}
				#summary_table td:nth-child(1):hover {background-color: #4169e1 !important}
				.summary_button:hover {background-color: #4169e1 !important; color: white}

				.help_table{border: 1px; width: 100%; cellspacing:0; border-spacing:0; border-collapse:collapse; display: block}
				.help_table th{color: black; text-decoration: none;border: solid 1px; padding:5px; margin:0}
				.help_table td {border: solid 1px; padding: 5px; margin:0}
				.help_caption {border:0px solid black; font-weight: bold; font-size: 1.5em; padding-left: 5px; padding-right: 5px ; color:brown }
				.caption {border:1px solid black; font-weight: bold; font-size: 1.5em; padding-left: 5px; padding-right: 5px  }

				#frame_table{border: 1px; width: 100%; cellspacing:0; border-spacing:0; border-collapse:collapse; display: block}
				#frame_table th{color: black; text-decoration: none;border: solid 1px; padding:5px; margin:0}
				#frame_table td {border: solid 1px; padding: 5px; margin:0}
				#frame_table_caption {border:1px solid black; font-weight: bold; font-size: 1.5em; padding-left: 5px; padding-right: 5px  }
				
				.frame_row {display:none}
				#frame_table th:hover {background-color: #4169e1 !important}
				#frame_table td:nth-child(2):hover {background-color: #4169e1 !important}
				#frame_table td:nth-child(3):hover {background-color: #4169e1 !important}
				#frame_table td:nth-child(4):hover {background-color: #4169e1 !important}
				#frame_table tr:hover {cursor: pointer;}
				caption{font-size: 1em; margin: 10px; font-weight: bold; color:#4169e1}
				.top_table{margin-left:0px;border: 1px; width: 100%; display: block; text-align:center; border-collapse:collapse;}
				.top_table th{color: black; text-decoration: none;border: solid 1px; padding:5px; margin:0}
				.top_table td {border: solid 1px; padding: 5px; margin:0; background:white; color: #4169e1}
				.top_table tr {width: 100%}
				.top_table th:hover {background-color: #4169e1 !important; color:white !important}
				h4 {margin-left: 20px; padding: 5px; margin: 5px; color: #4169e1}
								
				#help_div{position: absolute; left:0%; top:0%; width:33%; height: 100%; border:1px solid #4169e1; display: none; overflow:auto}
				#main_div {position: absolute; left:0%; top:0%; width:100%; height:100%; display: block}
				#top_div  {position: absolute; left:1%; top:1%; width:98%; height:5%; display: block; border: 1px solid black; background: white;}
				#summary_div{position: absolute; left:1%; top:6%; width:98%; height: 93%; border:1px solid #4169e1; display: block; overflow:auto}
				#frame_div{position: absolute; left:1%; top:6%; width:98%; height: 93%; border:1px solid #4169e1; display: none; overflow:auto}
            </style>
            <script type="text/javascript">
				<xsl:text disable-output-escaping="yes">
					<![CDATA[
						function show_help(){
							help_div = document.getElementById("help_div");
							main_div = document.getElementById("main_div");
							if(help_div.style.display==='block'){
								help_div.style.display = 'none';
								main_div.style.left = "0%";
								main_div.style.width = "100%";
							}
							else{
								help_div.style.display = 'block';
								main_div.style.left = "34%";
								main_div.style.width = "65%";
							}
						}
						function highlight_summary_buttons(button){
							els = document.getElementsByClassName("summary_button");
							for(let x=0; x<els.length; x++){
								els[x].style.backgroundColor = 'white';
								els[x].style.color = '#4169e1';
								if(els[x].innerHTML === button){
									els[x].style.color = 'white';
									els[x].style.backgroundColor = '#4169e1';
								}
							}
						}
						function clear_frame_rows(){
							const els = document.getElementsByClassName('framerow');
							for(let x=0; x<els.length; x++){
								els[x].style.display = 'none';
							}
						}
						function show_error(key){
							clear_frame_rows();
							els = document.getElementsByClassName(key);
							for(let x=0; x<els.length; x++){
								els[x].style.display = 'table-row';
							}
							//highlight_summary_buttons("");
						}
						function show_all_frame_rows(){
							one_frame = document.getElementById("one_frame");
							clear_frame_rows();
							if(one_frame.checked){
								els = document.getElementsByClassName('framerow last_');
							}
							else{
								els = document.getElementsByClassName('framerow');
							}
							for(let x=0; x<els.length; x++){
								els[x].style.display = 'table-row';
							}
							//highlight_summary_buttons("");
						}
						function show_frame_row_process(process){
                            if(process==="All"){
                                show_all_frame_rows();
                            }
                            else{
                                clear_frame_rows();
								one_frame = document.getElementById("one_frame");
								if(one_frame.checked){
									els = document.getElementsByClassName(process + "_framerow last_" );
								}
								else{
									els = document.getElementsByClassName(process + "_framerow" );
								}
                                for(let x=0; x<els.length; x++){
                                    els[x].style.display = 'table-row';
                                }
                                caption = document.getElementById("frame_table_caption");
                            }
                            caption.innerHTML = "Frame Table - " + process;
                            //highlight_summary_buttons("");
							frame_div.style.display = 'block';
							summary_div.style.display = 'none';
						}
						
						function show_kind_row(kind){
							one_frame = document.getElementById("one_frame");
                            if(kind==="All"){
                                show_all_frame_rows();
                            }
                            else{
                                clear_frame_rows();
								if(one_frame.checked){
									els = document.getElementsByClassName(kind + " last_");
								}
								else{
									els = document.getElementsByClassName(kind);
								}
                                
                                for(let x=0; x<els.length; x++){
								    els[x].style.display = 'table-row';
                                }
                                caption = document.getElementById("frame_table_caption");
                            }
                            caption.innerHTML = "Frame Table - " + kind;
                            frame_div.style.display = 'block';
							summary_div.style.display = 'none';
							//highlight_summary_buttons(kind);
						}
						var SyscallParam = 0;
						var Leak_StillReachable = 0;
						var Leak_PossiblyLost = 0;
						var Leak_IndirectlyLost = 0;
						var Leak_DefinitelyLost = 0;
						var InvalidWrite = 0;
						var InvalidRead = 0;
						var TotalErrors = 0;
						function get_stats(){
                            SyscallParam = 0;
                            Leak_StillReachable = 0;
                            Leak_PossiblyLost = 0;
                            Leak_IndirectlyLost = 0;
                            Leak_DefinitelyLost = 0;
                            InvalidWrite = 0;
                            InvalidRead = 0;
                            TotalErrors = 0;
							table = document.getElementById("frame_table");
							rows = table.rows;
							var hex;
							var cell;
							var error;
                            var order = -1;
							for (var x=1; x<rows.length; x++){
                                if (rows[x].style.display == "table-row"){
                                    cellorder = parseInt(rows[x].getElementsByTagName("td")[2].innerHTML);
                                    if (cellorder !== order){
                                        order = cellorder;
                                        error = rows[x].getElementsByTagName("td")[3].innerHTML;
                                        TotalErrors++;
                                        if(error === "InvalidWrite"){InvalidWrite++;}
                                        if(error === "InvalidRead"){InvalidRead++;}
                                        if(error === "Leak_StillReachable"){Leak_StillReachable++;}
                                        if(error === "Leak_PossiblyLost"){Leak_PossiblyLost++;}
                                        if(error === "Leak_IndirectlyLost"){Leak_IndirectlyLost++;}
                                        if(error === "Leak_DefinitelyLost"){Leak_DefinitelyLost++;}
                                        if(error === "SyscallParam"){SyscallParam++;}
                                    }

                                }
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
						}
						
                        function sortTable(table_name,column, isNumeric){
                            const table = document.getElementById(table_name);
                            const tbody = table.tBodies[0];
                            const rows = Array.from(tbody.rows);
                            const isAscending = table.dataset.sortOrder !== "asc";
                            table.dataset.sortOrder = isAscending ? "asc" : "desc";
                            rows.sort((rowA, rowB) => {
                                const cellA = rowA.cells[column].textContent.trim();
                                const cellB = rowB.cells[column].textContent.trim();
                                //if (cellA.length === 0) {cellA = "ZZZZZZ";}
                                //if (cellB.length === 0) {cellB = "ZZZZZZ";}
                                const valueA = isNaN(cellA) ? cellA : parseFloat(cellA);
                                const valueB = isNaN(cellB) ? cellB : parseFloat(cellB);                        
                                if (valueA < valueB) return isAscending ? -1 : 1;
                                if (valueA > valueB) return isAscending ? 1 : -1;
                                return 0;
                            });
                            tbody.append(...rows);
                        }
						function toggle_divs(){
							frame_div = document.getElementById("frame_div");
							summary_div = document.getElementById("summary_div");
							if(frame_div.style.display==='block'){
								frame_div.style.display = 'none';
								summary_div.style.display = 'block';
							}
							else{
								frame_div.style.display = 'block';
								summary_div.style.display = 'none';
							}
						}
                    ]]>
				</xsl:text>
			</script>
			<body onload="">
            <div id="help_div">
				<table style="width:100%">
					<tr>
						<td class="help_caption">Valgrind Report Help</td>
						<td><input type="button" value="Close Help" onclick="show_help()" /></td>
					</tr>
				</table>
				<h4 class="help_caption">Summary Table</h4>
				<table class="help_table">
					<tr>
						<th>Show Frames</th>
						<td>Will show frames from all processes in this report.</td>
					</tr>
					<tr>
						<th></th>
						<td>If "show only last frame per error" is selected, it will do just that.</td>
					</tr>
					<tr>
						<th>Column Headers</th>
						<td>Clicking on any column header, will show frames for that particular error type for all processes.</td>
					</tr>
					<tr>
						<th>Process Column Cell</th>
						<td>Clicking on the process name, will show all frames for that particular process.</td>
					</tr>
				</table>
				<h4 class="help_caption">Frame Table</h4>
				<table class="help_table">
					<tr>
						<th>Column Headers</th>
						<td>Clicking on any column header, will sort the table by that column.</td>
					</tr>
					<tr>
						<th>Process Column Cell</th>
						<td>Clicking on the process name, will show all frames for that particular process.</td>
					</tr>
					<tr>
						<th>Error Column Cell</th>
						<td>Clicking on the error number, will show all frames for that particular error.</td>
					</tr>
					<tr>
						<th>Kind Column Cell</th>
						<td>Clicking on the error kind, will show all frames for that particular error kind.</td>
					</tr>
				</table>
			</div>
			<div id="main_div">
			<div id="top_div">
				<h4>Valgrind <xsl:value-of select="valgrind_trace/summary/@Date"/></h4>
			</div>		
			<div id="summary_div">
				<table class="top_table">
					<tr>
						<td class="caption">Summary Table</td>
						<td><input type="button" value="Show Frames" onclick="toggle_divs()" /></td>
						<td>show only last frame per error</td>
						<td><input type="checkbox" name="one_frame" id="one_frame" checked="false"/></td>
						<td><input type="button" value="Show Help" onclick="show_help()" /></td>
					</tr>
				</table>
				<table id="summary_table">
					<tr>
						<th>Process</th>
						<th class="summary_button" onclick="show_kind_row('All')">TotalErrors</th>
						<th class="summary_button" onclick="show_kind_row('InvalidWrite')">InvalidWrite</th>
						<th class="summary_button" onclick="show_kind_row('InvalidRead')">InvalidRead</th>
						<th class="summary_button" onclick="show_kind_row('SyscallParam')">SyscallParam</th>
						<th class="summary_button" onclick="show_kind_row('Leak_DefinitelyLost')">Leak_DefinitelyLost</th>
						<th class="summary_button" onclick="show_kind_row('Leak_PossiblyLost')">Leak_PossiblyLost</th>
						<th class="summary_button" onclick="show_kind_row('Leak_IndirectlyLost')">Leak_IndirectlyLost</th>
						<th class="summary_button" onclick="show_kind_row('Leak_StillReachable')">Leak_StillReachable</th>
					</tr>
					<xsl:for-each select="valgrind_trace/summary/process">
						<tr>
							<td>
								<xsl:attribute name="onclick">show_frame_row_process('<xsl:value-of select="@name"/>')</xsl:attribute>
								<xsl:value-of select="@name"/>
							</td>
							<td><xsl:value-of select="@TotalErrors"/></td>
							<td><xsl:value-of select="@InvalidWrite"/></td>
							<td><xsl:value-of select="@InvalidRead"/></td>
							<td><xsl:value-of select="@SyscallParam"/></td>
							<td><xsl:value-of select="@Leak_DefinitelyLost"/></td>
							<td><xsl:value-of select="@Leak_PossiblyLost"/></td>
							<td><xsl:value-of select="@Leak_IndirectlyLost"/></td>
							<td><xsl:value-of select="@Leak_StillReachable"/></td>
						</tr>
					</xsl:for-each>
					<tr>
						<th>Total</th>
						<th><xsl:value-of select="valgrind_trace/summary/@TotalErrors"/></th>
						<th><xsl:value-of select="valgrind_trace/summary/@InvalidWrite"/></th>
						<th><xsl:value-of select="valgrind_trace/summary/@InvalidRead"/></th>
						<th><xsl:value-of select="valgrind_trace/summary/@SyscallParam"/></th>
						<th><xsl:value-of select="valgrind_trace/summary/@Leak_DefinitelyLost"/></th>
						<th><xsl:value-of select="valgrind_trace/summary/@Leak_PossiblyLost"/></th>
						<th><xsl:value-of select="valgrind_trace/summary/@Leak_IndirectlyLost"/></th>
						<th><xsl:value-of select="valgrind_trace/summary/@Leak_StillReachable"/></th>
					</tr>
				</table>
			</div>
			<div id="frame_div">
			<table class="top_table">
				<tr>
					<td id="frame_table_caption">Frame Table - All</td>
					<td><input type="button" value="Back to Summary" onclick="toggle_divs()" /></td>
					<td><input type="button" value="Show Help" onclick="show_help()" /></td>
				</tr>
			</table>
			<table id="frame_table">
				<thead>
                <tr>
					<th onclick="sortTable('frame_table', 0, 0)">ord#</th>
                    <th onclick="sortTable('frame_table', 1, 0)">process</th>
                    <th onclick="sortTable('frame_table', 2, 1)">error#</th>
                    <th onclick="sortTable('frame_table', 3, 0)">kind</th>
                    <th onclick="sortTable('frame_table', 4, 1)">lbytes</th>
                    <th onclick="sortTable('frame_table', 5, 1)">lblocks</th>
                    <th onclick="sortTable('frame_table', 6, 1)">frame#</th>
                    <th onclick="sortTable('frame_table', 7, 0)">ip</th>
                    <th onclick="sortTable('frame_table', 8, 0)">obj</th>
                    <th onclick="sortTable('frame_table', 9, 0)">dir</th>
                    <th onclick="sortTable('frame_table', 10, 0)">file</th>
                    <th onclick="sortTable('frame_table', 11, 1)">line#</th>
                    <th style="width: 10px;" onclick="sortTable('frame_table', 12, 0)">fn</th>
                </tr>
				</thead>
				<tbody>
            	<xsl:for-each select="valgrind_trace/error">
                <xsl:for-each select="frame">
                <tr style="display: table-row">
					<xsl:choose>
						<xsl:when test="position() = 1">
							<xsl:attribute name="class">first_ <xsl:value-of select="../@process"/><xsl:value-of select="../@unique_dec"/>_ framerow <xsl:value-of select="../@process"/>_framerow <xsl:value-of select="../@kind"/> _<xsl:value-of select="@order"/></xsl:attribute>
						</xsl:when>
						<xsl:when test="position() = last()">
							<xsl:attribute name="class">last_ <xsl:value-of select="../@process"/><xsl:value-of select="../@unique_dec"/>_ framerow <xsl:value-of select="../@process"/>_framerow <xsl:value-of select="../@kind"/> _<xsl:value-of select="@order"/></xsl:attribute>
						</xsl:when>
						<xsl:otherwise>
							<xsl:attribute name="class"><xsl:value-of select="../@process"/><xsl:value-of select="../@unique_dec"/>_ framerow <xsl:value-of select="../@process"/>_framerow <xsl:value-of select="../@kind"/> _<xsl:value-of select="@order"/></xsl:attribute>
						</xsl:otherwise>
					</xsl:choose>
                    
					<td><xsl:value-of select="@all_count"/></td>
					<td>
						<xsl:attribute name="onclick">show_frame_row_process('<xsl:value-of select="../@process"/>')</xsl:attribute>
						<xsl:value-of select="../@process"/>
					</td>
                    <td>
						<xsl:attribute name="onclick">show_error('<xsl:value-of select="../@process"/><xsl:value-of select="../@unique_dec"/>_')</xsl:attribute>
						<xsl:value-of select="../@unique_dec"/>
					</td>
					<td>
						<xsl:attribute name="onclick">show_kind_row('<xsl:value-of select="../@kind"/>')</xsl:attribute>
						<xsl:value-of select="../@kind"/>
					</td>
                    <td><xsl:value-of select="../@leakedbytes"/></td>
                    <td><xsl:value-of select="../@leakedblocks"/></td>
                    <td><xsl:value-of select="@order"/></td>
                    <td><xsl:value-of select="@ip"/></td>
                    <td><xsl:value-of select="@obj"/></td>
                    <td><xsl:value-of select="@dir"/></td>
					<td><xsl:value-of select="@file"/></td>
					<td><xsl:value-of select="@line"/></td>
                    <td style="text-overflow: ellipsis; width: 50px"><xsl:value-of select="@fn"/></td>
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