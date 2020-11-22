<?php

function list_files($path)
{
    global $exts;

    config_oauth();
    $refresh_token = getConfig('refresh_token');
    if (!$refresh_token) return '';

    if (!($_SERVER['access_token'] = getcache('access_token', $_SERVER['disktag']))) {
        $response = get_access_token($refresh_token);
        if (isset($response['stat'])) return message($response['body'], 'Error', $response['stat']);
    }
//return tttt($path, $_SERVER['access_token']);
    $_SERVER['ishidden'] = passhidden($path);
    if (isset($_GET['thumbnails'])) {
        if ($_SERVER['ishidden']<4) {
            if (in_array(strtolower(substr($path, strrpos($path, '.') + 1)), $exts['img'])) {
                return get_thumbnails_url($path, $_GET['location']);
            } else return output(json_encode($exts['img']), 400);
        } else return output('', 401);
    }

    $path = path_format($path);
    //error_log($path);
    if ($_SERVER['is_guestup_path']&&!$_SERVER['admin']) {
        $files = json_decode('{"folder":{}}', true);
    } elseif (!getConfig('downloadencrypt')) {
        if ($_SERVER['ishidden']==4) $files = json_decode('{"folder":{}}', true);
        else $files = fetch_files($path);
    } else {
        $files = fetch_files($path);
    }
//return $files;
    if ($_GET['json']) {
        // return a json
        return files_json($files);
    }
    if (isset($_GET['random'])&&$_GET['random']!=='') {
        if ($_SERVER['ishidden']<4) {
            $tmp = [];
            foreach (array_keys($files['children']) as $filename) {
                if (strtolower(splitlast($filename,'.')[1])==strtolower($_GET['random'])) $tmp[$filename] = $files['children'][$filename][$_SERVER['DownurlStrName']];
            }
            $tmp = array_values($tmp);
            if (count($tmp)>0) {
                $url = $tmp[rand(0,count($tmp)-1)];
                if (isset($_GET['url'])) return output($url, 200);
                $domainforproxy = '';
                $domainforproxy = getConfig('domainforproxy');
                if ($domainforproxy!='') {
                    $url = proxy_replace_domain($url, $domainforproxy);
                }
                return output('', 302, [ 'Location' => $url ]);
            } else return output('',404);
        } else return output('',401);
    }
    if (isset($files['file']) && !isset($_GET['preview'])) {
        // is file && not preview mode
        if ( $_SERVER['ishidden']<4 || (!!getConfig('downloadencrypt')&&$files['name']!=getConfig('passfile')) ) {
            $url = $files[$_SERVER['DownurlStrName']];
            $domainforproxy = '';
            $domainforproxy = getConfig('domainforproxy');
            if ($domainforproxy!='') {
                $url = proxy_replace_domain($url, $domainforproxy);
            }
            if ( strtolower(splitlast($files['name'],'.')[1])=='html' ) return output($files['content']['body'], $files['content']['stat']);
            else {
                if ($_SERVER['HTTP_RANGE']!='') $header['Range'] = $_SERVER['HTTP_RANGE'];
                $header['Location'] = $url;
                return output('', 302, $header);
            }
        }
    }
    if ( isset($files['folder']) || isset($files['file']) ) {
        return render_list($path, $files);
    } else {
        if (!isset($files['error'])) {
            $files['error']['message'] = json_encode($files, JSON_PRETTY_PRINT);
            $files['error']['code'] = 'unknownError';
            $files['error']['stat'] = 500;
        }
        return message('<a href="'.$_SERVER['base_path'].'">'.getconstStr('Back').getconstStr('Home').'</a><div style="margin:8px;"><pre>' . $files['error']['message'] . '</pre></div><a href="javascript:history.back(-1)">'.getconstStr('Back').'</a>', $files['error']['code'], $files['error']['stat']);
    }

    return $files;
}

function tttt($path, $access_token)
{
/*
    $url = 'https://graph.microsoft.com/v1.0/me';
    $arr = curl('GET', $url, '', [ 'Authorization' => 'Bearer ' . $access_token, 'Content-Type' => 'application/json' ], 1);
    //return output($arr['body'] . '<br>' . $access_token);
    $userid = json_decode($arr['body'], true)['id'];

    $url = 'https://graph.microsoft.com/v1.0/users/' . $userid . '/drive';
    $arr = curl('GET', $url, '', [ 'Authorization' => 'Bearer ' . $access_token, 'Content-Type' => 'application/json' ], 1);
    $driveid = json_decode($arr['body'], true)['id'];

    $url = 'https://graph.microsoft.com/v1.0/drives/' . $driveid . '/root/children';
    $arr = curl('GET', $url, '', [ 'Authorization' => 'Bearer ' . $access_token, 'Content-Type' => 'application/json' ], 1);
*/
    //$url = 'https://graph.microsoft.com/v1.0/me/followedSites';
    //$url = 'https://graph.microsoft.com/v1.0/sites/root:/sites/b';
    //$url = 'https://graph.microsoft.com/v1.0/sites/qkq.sharepoint.com,ddb6bb53-910d-410b-b6d0-8614939a9ac1,8a5fc581-b3c6-4f3a-8cec-6b10c10ddae3/drive/';
    //$url = 'https://graph.microsoft.com/v1.0/drives/b!U7u23Q2RC0G20IYUk5qawYHFX4rGszpPjOxrEMEN2uPZ0hEcAMPUQYsh2EnelzXd/root/children';
    $url = 'https://microsoftgraph.chinacloudapi.cn/v1.0/me';
    //$url = 'https://microsoftgraph.chinacloudapi.cn/v1.0/me/followedSites';
    $arr = curl('GET', $url, '', [ 'Authorization' => 'Bearer ' . $access_token, 'Content-Type' => 'application/json' ], 1);

    return output( $url . '<br>' . $arr['stat'] . '<br>' . json_encode(json_decode($arr['body']), JSON_PRETTY_PRINT)  . '<br>' . $access_token );

}

function operate($path)
{
    config_oauth();
    if (!($_SERVER['access_token'] = getcache('access_token', $_SERVER['disktag']))) {
        $refresh_token = getConfig('refresh_token');
        if (!$refresh_token) {
            $html = 'No refresh_token config, please AddDisk again or wait minutes.<br>' . $_SERVER['disktag'];
            $title = 'Error';
            return message($html, $title, 201);
        }
        $response = get_access_token($refresh_token);
        if (isset($response['stat'])) return message($response['body'], 'Error', $response['stat']);
    }

    if ($_SERVER['ajax']) {
        if ($_GET['action']=='del_upload_cache') {
            // del '.tmp' without login. 无需登录即可删除.tmp后缀文件
            error_log('del.tmp:GET,'.json_encode($_GET,JSON_PRETTY_PRINT));
            $tmp = splitlast($_GET['filename'], '/');
            if ($tmp[1]!='') {
                $filename = $tmp[0] . '/.' . $_GET['filelastModified'] . '_' . $_GET['filesize'] . '_' . $tmp[1] . '.tmp';
            } else {
                $filename = '.' . $_GET['filelastModified'] . '_' . $_GET['filesize'] . '_' . $_GET['filename'] . '.tmp';
            }
            $filename = path_format( path_format($_SERVER['list_path'] . path_format($path)) . '/' . spurlencode($filename, '/') );
            $tmp = MSAPI('DELETE', $filename, '', $_SERVER['access_token']);
            $path1 = path_format($_SERVER['list_path'] . path_format($path));
            if ($path1!='/'&&substr($path1,-1)=='/') $path1=substr($path1,0,-1);
            savecache('path_' . $path1, json_decode('{}',true), $_SERVER['disktag'], 1);
            return output($tmp['body'],$tmp['stat']);
        }
        if ($_GET['action']=='uploaded_rename') {
            // rename .scfupload file without login.
            // 无需登录即可重命名.scfupload后缀文件，filemd5为用户提交，可被构造，问题不大，以后处理
            $oldname = spurlencode($_GET['filename']);
            $pos = strrpos($oldname, '.');
            if ($pos>0) $ext = strtolower(substr($oldname, $pos));
            //$oldname = path_format(path_format($_SERVER['list_path'] . path_format($path)) . '/' . $oldname . '.scfupload' );
            $oldname = path_format(path_format($_SERVER['list_path'] . path_format($path)) . '/' . $oldname);
            $data = '{"name":"' . $_GET['filemd5'] . $ext . '"}';
            //echo $oldname .'<br>'. $data;
            $tmp = MSAPI('PATCH',$oldname,$data,$_SERVER['access_token']);
            if ($tmp['stat']==409) {
                MSAPI('DELETE',$oldname,'',$_SERVER['access_token']);
                $tmpbody = json_decode($tmp['body'], true);
                $tmpbody['name'] = $_GET['filemd5'] . $ext;
                $tmp['body'] = json_encode($tmpbody);
            }
            $path1 = path_format($_SERVER['list_path'] . path_format($path));
            if ($path1!='/'&&substr($path1,-1)=='/') $path1=substr($path1,0,-1);
            savecache('path_' . $path1, json_decode('{}',true), $_SERVER['disktag'], 1);
            return output($tmp['body'],$tmp['stat']);
        }
        if ($_GET['action']=='upbigfile') return bigfileupload($path);
    }
    if ($_SERVER['admin']) {
        $tmp = adminoperate($path);
        if ($tmp['statusCode'] > 0) {
            $path1 = path_format($_SERVER['list_path'] . path_format($path));
            if ($path1!='/'&&substr($path1,-1)=='/') $path1=substr($path1,0,-1);
            savecache('path_' . $path1, json_decode('{}',true), $_SERVER['disktag'], 1);
            return $tmp;
        }
    } else {
        if ($_SERVER['ajax']) return output(getconstStr('RefreshtoLogin'),401);
    }
}


function adminoperate($path)
{
    return output('天翼不提供操作', 400);

    $path1 = path_format($_SERVER['list_path'] . path_format($path));
    if (substr($path1,-1)=='/') $path1=substr($path1,0,-1);
    $tmparr['statusCode'] = 0;
    if (isset($_GET['rename_newname'])&&$_GET['rename_newname']!=$_GET['rename_oldname'] && $_GET['rename_newname']!='') {
        // rename 重命名
        if ($_GET['rename_isfile']==='file') {
            $data['fileId'] = $_GET['rename_fid'];
            $data['destFileName'] = $_GET['rename_newname'];
            $result = CTAPI($_SERVER['access_token'], $_SERVER['appSecret'], 'POST', 'renameFile', [], $data);
        } elseif ($_GET['rename_isfile']==='folder') {
            $data['folderId'] = $_GET['rename_fid'];
            $data['destFolderName'] = $_GET['rename_newname'];
            $result = CTAPI($_SERVER['access_token'], $_SERVER['appSecret'], 'POST', 'renameFolder', [], $data);
        }
        if ($result['stat']==200) $result['body'] = json_encode(json_decode($result['body'], true)[0]);
        return output($result['body'], $result['stat']);
    }
    if (isset($_GET['delete_name'])) {
        // delete 删除
        if ($_GET['delete_isfile']==='file') {
            $data = 'fileId=' . $_GET['delete_fid'];
            $data .= '&forcedDelete=0';
            $result = CTAPI($_SERVER['access_token'], $_SERVER['appSecret'], 'POST', 'deleteFile', [], $data);
        } elseif ($_GET['delete_isfile']==='folder') {
            //$data['folderId'] = $_GET['delete_fid'];
            //$data['forcedDelete'] = 0;
            $data = 'folderId=' . $_GET['delete_fid'];
            $data .= '&forcedDelete=0';
            $result = CTAPI($_SERVER['access_token'], $_SERVER['appSecret'], 'POST', 'deleteFolder', [], $data);
        }
        if ($result['stat']==200) $result['body'] = json_encode(json_decode($result['body'], true)[0]);
        //$filename = spurlencode($_GET['delete_name']);
        //$filename = path_format($path1 . '/' . $filename);
                //echo $filename;
        //$result = MSAPI('DELETE', $filename, '', $_SERVER['access_token']);
        //savecache('path_' . $path1, json_decode('{}',true), $_SERVER['disktag'], 1);
        return output($result['body'], $result['stat']);
    }
    if (isset($_GET['operate_action'])&&$_GET['operate_action']==getconstStr('Encrypt')) {
        // encrypt 加密
        if (getConfig('passfile')=='') return message(getconstStr('SetpassfileBfEncrypt'),'',403);
        if ($_GET['encrypt_folder']=='/') $_GET['encrypt_folder']=='';
        $foldername = spurlencode($_GET['encrypt_folder']);
        $filename = path_format($path1 . '/' . $foldername . '/' . urlencode(getConfig('passfile')));
                //echo $foldername;
        $result = MSAPI('PUT', $filename, $_GET['encrypt_newpass'], $_SERVER['access_token']);
        $path1 = path_format($path1 . '/' . $foldername );
        if ($path1!='/'&&substr($path1,-1)=='/') $path1=substr($path1,0,-1);
        savecache('path_' . $path1 . '/?password', '', $_SERVER['disktag'], 1);
        return output($result['body'], $result['stat']);
    }
    if (isset($_GET['move_folder'])) {
        // move 移动
        $moveable = 1;
        if ($path == '/' && $_GET['move_folder'] == '/../') $moveable=0;
        if ($_GET['move_folder'] == $_GET['move_name']) $moveable=0;
        if ($moveable) {
            if ($_GET['move_isfile']==='file') {
                $data['fileId'] = $_GET['move_fid'];
                //$data = 'fileId=' . $_GET['move_fid'];

                    $dest = path_format(urldecode($path) . '/' . $_GET['move_folder']);
                    if (substr($dest, -1)=='/') $dest = substr($dest, 0, -1);
                    $parentdest = splitlast($dest, '/')[0];
                    if ($parentdest==='') $parentdest = '/';
                    $parent = fetch_files($parentdest);
//error_log(json_encode($parent));
                    $parentid = $parent['children'][$_GET['move_folder']]['id'];
                    $data['destParentFolderId'] = $parentid;
                    //$data .= '&destParentFolderId=' . $parentid;
                //}
                $result = CTAPI($_SERVER['access_token'], $_SERVER['appSecret'], 'POST', 'moveFile', [], $data);

                if ($result['stat']==200) $result['body'] = json_encode(json_decode($result['body'], true)[0]);
            } elseif ($_GET['move_isfile']==='folder') {
                return output('{"error":"Can not move Folder"}', 400);

                $data = 'folderId=' . $_GET['move_fid'];
                //$data['destFolderName'] = '';
                //if ($_GET['move_folder'] == '/../') {
                //    $data['destParentFolderId'] = $_GET['move_pid'];
                //} else {
                    $dest = path_format(urldecode($path) . '/' . $_GET['move_folder']);
                    if (substr($dest, -1)=='/') $dest = substr($dest, 0, -1);
                    $parentdest = splitlast($dest, '/')[0];
                    if ($parentdest==='') $parentdest = '/';
                    $parent = fetch_files($parentdest);
//error_log(json_encode($parent));
                    $parentid = $parent['children'][$_GET['move_folder']]['id'];
                    $data .= '&destParentFolderId' . $parentid;
                //}
                $result = CTAPI($_SERVER['access_token'], $_SERVER['appSecret'], 'POST', 'moveFolder', [], $data);

                if ($result['stat']==200) $result['body'] = json_encode(json_decode($result['body'], true)[0]);
            }
            /*$filename = spurlencode($_GET['move_name']);
            $filename = path_format($path1 . '/' . $filename);
            $foldername = path_format('/'.urldecode($path1).'/'.$_GET['move_folder']);
            $data = '{"parentReference":{"path": "/drive/root:'.$foldername.'"}}';
            $result = MSAPI('PATCH', $filename, $data, $_SERVER['access_token']);*/
            //savecache('path_' . $path1, json_decode('{}',true), $_SERVER['disktag'], 1);
            if ($_GET['move_folder'] == '/../') $path2 = path_format( substr($path1, 0, strrpos($path1, '/')) . '/' );
            else $path2 = path_format( $path1 . '/' . $_GET['move_folder'] . '/' );
            if ($path2!='/'&&substr($path2,-1)=='/') $path2=substr($path2,0,-1);
            savecache('path_' . $path2, json_decode('{}',true), $_SERVER['disktag'], 1);
            return output($result['body'], $result['stat']);
        } else {
            return output('{"error":"'.getconstStr('CannotMove').'"}', 403);
        }
    }
    if (isset($_GET['copy_name'])) {
        // copy 复制
        if ($_GET['copy_isfile']==='folder') return output('{"error":"Can not copy Folder"}', 400);

        $filename = spurlencode($_GET['copy_name']);
        //$filename = path_format($path1 . '/' . $filename);
        $namearr = splitlast($_GET['copy_name'], '.');
        if ($namearr[0]!='') {
            $newname = $namearr[0] . ' (' . getconstStr('Copy') . ')';
            if ($namearr[1]!='') $newname .= '.' . $namearr[1];
        } else {
            $newname = '.' . $namearr[1] . ' (' . getconstStr('Copy') . ')';
        }

        $data['fileId'] = $_GET['copy_fid'];
        $data['destFileName'] = $newname;
        $data['destParentFolderId'] = $_GET['copy_pid'];
        $result = CTAPI($_SERVER['access_token'], $_SERVER['appSecret'], 'POST', 'copyFile', [], $data);

        if ($result['stat']==200) $result['body'] = json_encode(json_decode($result['body'], true)[0]);

        $num = 0;
        while ($result['stat']==400 && json_decode($result['body'], true)['error']['code']=='FileAlreadyExists') {
            $num++;
            if ($namearr[0]!='') {
                $newname = $namearr[0] . ' (' . getconstStr('Copy') . ' ' . $num . ')';
                if ($namearr[1]!='') $newname .= '.' . $namearr[1];
            } else {
                $newname = '.' . $namearr[1] . ' ('.getconstStr('Copy'). ' ' . $num .')';
            }
            //$newname = spurlencode($newname);
            $data['fileId'] = $_GET['copy_fid'];
            $data['destFileName'] = $newname;
            $data['destParentFolderId'] = $_GET['copy_pid'];
            //$result = MSAPI('copy', $filename, $data, $_SERVER['access_token']);
            $result = CTAPI($_SERVER['access_token'], $_SERVER['appSecret'], 'POST', 'copyFile', [], $data);

            if ($result['stat']==200) $result['body'] = json_encode(json_decode($result['body'], true)[0]);
        }
        //echo $result['stat'].$result['body'];
            //savecache('path_' . $path1, json_decode('{}',true), $_SERVER['disktag'], 1);
            //if ($_GET['move_folder'] == '/../') $path2 = path_format( substr($path1, 0, strrpos($path1, '/')) . '/' );
            //else $path2 = path_format( $path1 . '/' . $_GET['move_folder'] . '/' );
            //savecache('path_' . $path2, json_decode('{}',true), $_SERVER['disktag'], 1);
        return output($result['body'], $result['stat']);
    }
    if (isset($_POST['editfile'])) {
        // edit 编辑
        $data = $_POST['editfile'];
        /*TXT一般不会超过4M，不用二段上传
        $filename = $path1 . ':/createUploadSession';
        $response=MSAPI('POST',$filename,'{"item": { "@microsoft.graph.conflictBehavior": "replace"  }}',$_SERVER['access_token']);
        $uploadurl=json_decode($response,true)['uploadUrl'];
        echo MSAPI('PUT',$uploadurl,$data,$_SERVER['access_token']);*/
        $result = MSAPI('PUT', $path1, $data, $_SERVER['access_token'])['body'];
        //echo $result;
        $resultarry = json_decode($result,true);
        if (isset($resultarry['error'])) return message($resultarry['error']['message']. '<hr><a href="javascript:history.back(-1)">'.getconstStr('Back').'</a>','Error',403);
    }
    if (isset($_GET['create_name'])) {
        // create 新建
        if ($_GET['create_type']=='file') {
            
            //$filename = path_format($path1 . '/' . $filename);
            //$result = MSAPI('PUT', $filename, , $_SERVER['access_token']);
            
            $filename = spurlencode($_GET['create_name']);
            $tmpfile = sys_get_temp_dir() . '/' . $filename;
            file_put_contents($tmpfile, $_GET['create_text']);
            $header['Edrive-ParentFolderId'] = '295423744';
            $header['Edrive-BaseFileId'] = '';
            $header['Edrive-FileName'] = $filename;
            $header['Edrive-FileMD5'] = md5_file($tmpfile);
            $header['Content-Length'] = strlen($_GET['create_text']);

            $result = CTAPI($_SERVER['access_token'], $_SERVER['appSecret'], 'PUT', 'putFile', [], $_GET['create_text'], $header);
        }
        if ($_GET['create_type']=='folder') {
            $data['parentFolderId'] = '-11';
            $data['relativePath'] = urldecode($path1);
            $data['folderName'] = $_GET['create_name'];
            
            $result = CTAPI($_SERVER['access_token'], $_SERVER['appSecret'], 'POST', 'createFolder', [], $data);
        }
        
        if ($result['stat']==200) $result['body'] = json_encode(json_decode($result['body'], true)[0]);
        //savecache('path_' . $path1, json_decode('{}',true), $_SERVER['disktag'], 1);
        return output($result['body'], $result['stat']);
    }
    if (isset($_GET['RefreshCache'])) {
        $path1 = path_format($_SERVER['list_path'] . path_format($path));
        if ($path1!='/'&&substr($path1,-1)=='/') $path1=substr($path1,0,-1);
        savecache('path_' . $path1 . '/?password', '', $_SERVER['disktag'], 1);
        savecache('customTheme', '', '', 1);
        return message('<meta http-equiv="refresh" content="2;URL=./">', getconstStr('RefreshCache'), 302);
    }
    return $tmparr;
}

function Xml2Array($str)
{
    $tmp = null;
    $num = 0;
    while (strrpos($str, '</')) {
        $name = '';
        $value = '';
        $name = substr($str, strrpos($str, '</') + 2);
        $name = substr($name, 0, strpos($name, '>'));
        //echo $name . ' * ';
        $tmpstr = substr($str, 0, strrpos($str, '<' . $name . '>'));
        $str = substr($str, strrpos($str, '<' . $name . '>') + strlen('<' . $name . '>'));
        $value = substr($str, 0, strrpos($str, '</' . $name . '>'));
        $tmpstr .= substr($str, strrpos($str, '</' . $name . '>') + strlen('</' . $name . '>'));
        //echo $name . ' : ' . $value . PHP_EOL;
        if (strpos($value, '![CDATA[')===1) $value = substr($value, 9, -3);
        else $value = Xml2Array($value);
        if ($name!='folder' && $name!='file') {
            $tmp[$name] = $value;
        } else {
            $tmp[$num] = $value;
            $num++;
        }
        $str = $tmpstr;
    }

    if (!$tmp) return $str;
    return $tmp;
}

function get_access_token($refresh_token)
{
    $_SERVER['access_token'] = getConfig('access_token');
    return 1;
        $p=0;
        while ($response['stat']==0&&$p<3) {
            $response = curl_request( $_SERVER['oauth_url'] . 'token', 'client_id='. $_SERVER['client_id'] .'&client_secret='. $_SERVER['client_secret'] .'&grant_type=refresh_token&requested_token_use=on_behalf_of&refresh_token=' . $refresh_token );
            $p++;
        }
        if ($response['stat']==200) $ret = json_decode($response['body'], true);
        if (!isset($ret['access_token'])) {
            error_log($_SERVER['oauth_url'] . 'token'.'?client_id='. $_SERVER['client_id'] .'&client_secret='. $_SERVER['client_secret'] .'&grant_type=refresh_token&requested_token_use=on_behalf_of&refresh_token=' . substr($refresh_token, 0, 20) . '******' . substr($refresh_token, -20));
            error_log('failed to get ['.$_SERVER['disktag'].'] access_token. response' . json_encode($ret));
            $response['body'] = json_encode(json_decode($response['body']), JSON_PRETTY_PRINT);
            $response['body'] .= '\nfailed to get ['.$_SERVER['disktag'].'] access_token.';
            return $response;
            //throw new Exception($response['stat'].', failed to get ['.$_SERVER['disktag'].'] access_token.'.$response['body']);
        }
        $tmp = $ret;
        $tmp['access_token'] = '******';
        $tmp['refresh_token'] = '******';
        error_log('['.$_SERVER['disktag'].'] Get access token:'.json_encode($tmp, JSON_PRETTY_PRINT));
        $_SERVER['access_token'] = $ret['access_token'];
        savecache('access_token', $_SERVER['access_token'], $_SERVER['disktag'], $ret['expires_in'] - 300);
        if (time()>getConfig('token_expires')) setConfig([ 'refresh_token' => $ret['refresh_token'], 'token_expires' => time()+7*24*60*60 ]);
    
    return 0;
}

function config_oauth()
{
    $_SERVER['api_url'] = 'http://api.cloud.189.cn/listFiles.action';
    $_SERVER['oauth_url'] = 'https://cloud.189.cn/open/oauth2/';
    $_SERVER['appKey'] = '600000048';
    $_SERVER['appSecret'] = '3d556b7e07f9e62867d4defdc2f989a3';
    $_SERVER['appFolder'] = '189邮箱';
    //$_SERVER['appKey'] = '600102343';
    //$_SERVER['appSecret'] = '93c6a3491a5e1d93af0e44b470798148';
    //$_SERVER['appFolder'] = 'safebox';
    $_SERVER['callbackUrl'] = 'https://scfonedrive.github.io/CT/?install';
    $_SERVER['callbackUrl'] = urlencode($_SERVER['callbackUrl']);

    $_SERVER['scope'] = urlencode($_SERVER['scope']);
    $_SERVER['DownurlStrName'] = 'fileDownloadUrl';
}

function get_thumbnails_url($path = '/', $location = 0)
{
    $path1 = path_format($path);
    $path = path_format($_SERVER['list_path'] . path_format($path));
    if ($path!='/'&&substr($path,-1)=='/') $path=substr($path,0,-1);
    $thumb_url = getcache('thumb_'.$path, $_SERVER['disktag']);
    if ($thumb_url=='') {
        $url = $_SERVER['api_url'];
        if ($path !== '/') {
            $url .= ':' . $path;
            if (substr($url,-1)=='/') $url=substr($url,0,-1);
        }
        $url .= ':/thumbnails/0/medium';
        $files = json_decode(curl_request($url, false, ['Authorization' => 'Bearer ' . $_SERVER['access_token']])['body'], true);
        if (isset($files['url'])) {
            savecache('thumb_'.$path, $files['url'], $_SERVER['disktag']);
            $thumb_url = $files['url'];
        }
    }
    if ($thumb_url!='') {
        if ($location) {
            $url = $thumb_url;
            $domainforproxy = '';
            $domainforproxy = getConfig('domainforproxy');
            if ($domainforproxy!='') {
                $url = proxy_replace_domain($url, $domainforproxy);
            }
            return output('', 302, [ 'Location' => $url ]);
        } else return output($thumb_url);
    }
    return output('', 404);
}

function bigfileupload($path)
{
    return output('天翼不提供操作', 400);

    $path1 = path_format($_SERVER['list_path'] . path_format($path));
    if (substr($path1,-1)=='/') $path1=substr($path1,0,-1);
    if ($_GET['upbigfilename']!=''&&$_GET['filesize']>0) {
        $tmp = splitlast($_GET['upbigfilename'], '/');
        if ($tmp[1]!='') {
            $fileinfo['name'] = $tmp[1];
            $fileinfo['path'] = $tmp[0];
        } else {
            $fileinfo['name'] = $_GET['upbigfilename'];
        }
        $fileinfo['size'] = $_GET['filesize'];
        $fileinfo['lastModified'] = $_GET['lastModified'];
        $filename = spurlencode($_GET['upbigfilename'],'/');
        if ($fileinfo['size']>10*1024*1024) {
            $cachefilename = spurlencode( $fileinfo['path'] . '/.' . $fileinfo['lastModified'] . '_' . $fileinfo['size'] . '_' . $fileinfo['name'] . '.tmp', '/');
            $getoldupinfo=fetch_files(path_format($path . '/' . $cachefilename));
            //echo json_encode($getoldupinfo, JSON_PRETTY_PRINT);
            if (isset($getoldupinfo['file'])&&$getoldupinfo['size']<5120) {
                $getoldupinfo_j = curl_request($getoldupinfo[$_SERVER['DownurlStrName']]);
                $getoldupinfo = json_decode($getoldupinfo_j['body'], true);
                if ( json_decode( curl_request($getoldupinfo['uploadUrl'])['body'], true)['@odata.context']!='' ) return output($getoldupinfo_j['body'], $getoldupinfo_j['stat']);
            }
        }
        //if (!$_SERVER['admin']) $filename = spurlencode( $fileinfo['name'] ) . '.scfupload';
        $response = MSAPI('createUploadSession', path_format($path1 . '/' . $filename), '{"item": { "@microsoft.graph.conflictBehavior": "fail"  }}', $_SERVER['access_token']);
        if ($response['stat']<500) {
            $responsearry = json_decode($response['body'],true);
            if (isset($responsearry['error'])) return output($response['body'], $response['stat']);
            $fileinfo['uploadUrl'] = $responsearry['uploadUrl'];
            if ($fileinfo['size']>10*1024*1024) MSAPI('PUT', path_format($path1 . '/' . $cachefilename), json_encode($fileinfo, JSON_PRETTY_PRINT), $_SERVER['access_token']);
        }
        return output($response['body'], $response['stat']);
    }
    return output('error', 400);
}

function CTAPI($AccessToken, $SecretKey, $Operate, $Action, $Target = [], $Data = '', $header = [])
{
    //$Operate = 'GET';
    $Host = 'api.cloud.189.cn';
    //$RequestURI = '/listFiles.action';
    $RequestURI = '/' . $Action . '.action';
    $Date = substr(gmdate("r", time()), 0, -5) . 'GMT';
    $Signature = hash_hmac('sha1', 'AccessToken=' . $AccessToken . '&Operate=' . $Operate . '&RequestURI=' . $RequestURI . '&Date=' . $Date, $SecretKey);
    $header['AccessToken'] = $AccessToken;
    $header['Date'] = $Date;
    $header['Signature'] = $Signature;
    $header['Host'] = $Host;
    $url = 'http://' . $Host . $RequestURI;
    if ($Action=='listFiles') {
        $url .= '?folderId=' . $Target['id'] . '&fileType=&mediaType=&mediaAttr=&iconOption=&orderBy=filename&descending=&pageNum=&pageSize=';
    } elseif ($Action=='getFolderInfo') {
        if (isset($Target['id'])) $url .= '?folderId=' . $Target['id'];
        elseif ($Target['path']=='/') $url .= '?folderId=';
        else $url .= '?folderPath=' . $Target['path'];
    } elseif ($Action=='getFileInfo') {
        //SaveUserFileErrorCode
        if (isset($Target['id'])) $url .= '?fileId=' . $Target['id'] . '&mediaAttr=&iconOption=';
        //elseif ($Path=='/') $url .= '?fileId=null&mediaAttr=&iconOption=';
        else $url .= '?filePath=' . $Target['path'] . '&mediaAttr=&iconOption=';
    }
error_log($url);
error_log(json_encode($Data));
    $retry = 0;
    $arr = [];
    while ($retry<3&&!$arr['stat']) {
        $arr = curl($Operate, $url, $Data, $header);
        $retry++;
    }
error_log($arr['stat'] . $arr['body']);
    if ($arr['stat']<500) {
        $arr['body'] = json_encode(Xml2Array($arr['body']));
    }
    return $arr;
}

function fetch_files($path = '/')
{
    global $exts;
    $path1 = path_format($path);
    $path = path_format($_SERVER['list_path'] . path_format($path));
    //$path = path_format('/我的应用/189邮箱/' . $_SERVER['list_path'] . path_format($path));
    if ($path!='/'&&substr($path,-1)=='/') $path=substr($path,0,-1);
    if (!($files = getcache('path_' . $path, $_SERVER['disktag']))) {
        $pos = splitlast($path, '/');
        $parentpath = $pos[0];
        if ($parentpath=='') $parentpath = '/';
        $filename = $pos[1];
        if ($parentfiles = getcache('path_' . $parentpath, $_SERVER['disktag'])) {
            if (isset($parentfiles['children'][$filename][$_SERVER['DownurlStrName']])) {
                if (in_array(splitlast($filename,'.')[1], $exts['txt'])) {
                    if (!(isset($parentfiles['children'][$filename]['content'])&&$parentfiles['children'][$filename]['content']['stat']==200)) {
                        $content1 = curl('GET', $parentfiles['children'][$filename][$_SERVER['DownurlStrName']]);
                        $parentfiles['children'][$filename]['content'] = $content1;
                        //error_log($content1['body']);
                        savecache('path_' . $parentpath, $parentfiles, $_SERVER['disktag']);
                    }
                }
                return $parentfiles['children'][$filename];
            }
        }

        if ($path!='/') {
            //$tmp = json_decode(CTAPI($_SERVER['access_token'], $_SERVER['appSecret'], 'GET', 'mkt/userSign')['body'], true);
            //$tmp = json_decode(CTAPI($_SERVER['access_token'], $_SERVER['appSecret'], 'GET', 'listFiles', [ 'id' => $folderId ])['body'], true);
            //return $tmp;
            $tmp = json_decode(CTAPI($_SERVER['access_token'], $_SERVER['appSecret'], 'GET', 'getFileInfo', [ 'path' => $path ])['body'], true);
            if (isset($tmp['error'])) {
                $tmp['error']['message'] .= 'getFileInfo:' . $path;
                return $tmp;
            } elseif ($tmp['fileInfo']['md5']!='') {
                // 是文件
                $tmp = json_decode(CTAPI($_SERVER['access_token'], $_SERVER['appSecret'], 'GET', 'getFileInfo', [ 'path' => $path ])['body'], true);
                if (isset($tmp['error'])) {
                    $tmp['error']['message'] .= 'getFileInfo:' . $path;
                    return $tmp;
                } else {
                    $tmp['fileInfo']['fileDownloadUrl'] = str_replace('&amp;', '&', $tmp['fileInfo']['fileDownloadUrl']);
                    $tmp['fileInfo']['file'] = 1;
                    return $tmp['fileInfo'];
                }
            } else {
                // 是目录 getFolderInfo
                $folderId = $tmp['fileInfo']['id'];
                //return $tmp;
                $tmp = json_decode(CTAPI($_SERVER['access_token'], $_SERVER['appSecret'], 'GET', 'listFiles', [ 'id' => $folderId ])['body'], true);
                //return $tmp;
                $files['lastRev'] = $tmp['listFiles']['lastRev'];
                $files['children'] = $tmp['listFiles']['fileList'];
                $files['folder']['childCount'] = $files['children']['count'];
                unset($files['children']['count']);
                $files['children'] = children_name($files['children']);
                $files['id'] = $folderId;
                return $files;
            }
        } else {
            $tmp = json_decode(CTAPI($_SERVER['access_token'], $_SERVER['appSecret'], 'GET', 'listFiles')['body'], true);
            //return $tmp;
            $files['lastRev'] = $tmp['listFiles']['lastRev'];
            $files['children'] = $tmp['listFiles']['fileList'];
            $files['folder']['childCount'] = $files['children']['count'];
            unset($files['children']['count']);
            $files['children'] = children_name($files['children']);
            return $files;
        }
        

        //$tmp['body'] .= $path;
        //return $tmp;
        

            //echo $path . '<br><pre>' . json_encode($arr, JSON_PRETTY_PRINT) . '</pre>';
            if (isset($tmp['listFiles']['fileList'])) {
                if ($files['folder']['childCount']>200) {
                    // files num > 200 , then get nextlink
                    $page = $_POST['pagenum']==''?1:$_POST['pagenum'];
                    if ($page>1) $files=fetch_files_children($files, $path1, $page);
                    $files['children'] = children_name($files['children']);
                    /*$url = $_SERVER['api_url'];
                    if ($path !== '/') {
                        $url .= ':' . $path;
                        if (substr($url,-1)=='/') $url=substr($url,0,-1);
                        $url .= ':/children?$top=9999&$select=id,name,size,file,folder,parentReference,lastModifiedDateTime,'.$_SERVER['DownurlStrName'];
                    } else {
                        $url .= '/children?$top=9999&$select=id,name,size,file,folder,parentReference,lastModifiedDateTime,'.$_SERVER['DownurlStrName'];
                    }
                    $children = json_decode(curl_request($url, false, ['Authorization' => 'Bearer ' . $_SERVER['access_token']])['body'], true);
                    $files['children'] = $children['value'];*/
                } else {
                // files num < 200 , then cache
                    //if (isset($files['children'])) {
                        $files['children'] = children_name($files['children']);
                    //}
                    savecache('path_' . $path, $files, $_SERVER['disktag']);
                }
            }
            if (isset($files['file'])) {
                if (in_array(splitlast($files['name'],'.')[1], $exts['txt'])) {
                    if (!(isset($files['content'])&&$files['content']['stat']==200)) {
                        $content1 = curl_request($files[$_SERVER['DownurlStrName']]);
                        $files['content'] = $content1;
                        savecache('path_' . $path, $files, $_SERVER['disktag']);
                    }
                }
            }
            if (isset($files['error'])) {
                $files['error']['stat'] = $arr['stat'];
            }
        //} else {
            //error_log($arr['body']);
            $files = json_decode($arr['body'], true);
            if (isset($files['error'])) {
                $files['error']['stat'] = $arr['stat'];
            } else {
                $files['error']['stat'] = 503;
                $files['error']['code'] = 'unknownError';
                $files['error']['message'] = 'unknownError';
            }
            //$files = json_decode( '{"unknownError":{ "stat":'.$arr['stat'].',"message":"'.$arr['body'].'"}}', true);
            //error_log(json_encode($files, JSON_PRETTY_PRINT));
        //}
    }

    return $files;
}

function children_name($children)
{
    $tmp = [];
    foreach ($children as $file) {
        if (isset($file['md5'])) $file['file'] = 1;
        else $file['folder'] = 1;
        $file['lastModifiedDateTime'] = $file['lastOpTime'];
        unset($file['lastOpTime']);
        
        $tmp[strtolower($file['name'])] = $file;
    }
    return $tmp;
}

function fetch_files_children($files, $path, $page)
{
    $path1 = path_format($path);
    $path = path_format($_SERVER['list_path'] . path_format($path));
    if ($path!='/'&&substr($path,-1)=='/') $path=substr($path,0,-1);
    $cachefilename = '.SCFcache_'.$_SERVER['function_name'];
    $maxpage = ceil($files['folder']['childCount']/200);
    if (!($files['children'] = getcache('files_' . $path . '_page_' . $page, $_SERVER['disktag']))) {
        // down cache file get jump info. 下载cache文件获取跳页链接
        $cachefile = fetch_files(path_format($path1 . '/' .$cachefilename));
        if ($cachefile['size']>0) {
            $pageinfo = curl_request($cachefile[$_SERVER['DownurlStrName']])['body'];
            $pageinfo = json_decode($pageinfo,true);
            for ($page4=1;$page4<$maxpage;$page4++) {
                savecache('nextlink_' . $path . '_page_' . $page4, $pageinfo['nextlink_' . $path . '_page_' . $page4], $_SERVER['disktag']);
                $pageinfocache['nextlink_' . $path . '_page_' . $page4] = $pageinfo['nextlink_' . $path . '_page_' . $page4];
            }
        }
        $pageinfochange=0;
        for ($page1=$page;$page1>=1;$page1--) {
            $page3=$page1-1;
            $url = getcache('nextlink_' . $path . '_page_' . $page3, $_SERVER['disktag']);
            if ($url == '') {
                if ($page1==1) {
                    $url = $_SERVER['api_url'];
                    if ($path !== '/') {
                        $url .= ':' . $path;
                        if (substr($url,-1)=='/') $url=substr($url,0,-1);
                        $url .= ':/children?$select=id,name,size,file,folder,parentReference,lastModifiedDateTime,'.$_SERVER['DownurlStrName'];
                    } else {
                        $url .= '/children?$select=id,name,size,file,folder,parentReference,lastModifiedDateTime,'.$_SERVER['DownurlStrName'];
                    }
                    $children = json_decode(curl_request($url, false, ['Authorization' => 'Bearer ' . $_SERVER['access_token']])['body'], true);
                    // echo $url . '<br><pre>' . json_encode($children, JSON_PRETTY_PRINT) . '</pre>';
                    savecache('files_' . $path . '_page_' . $page1, $children['value'], $_SERVER['disktag']);
                    $nextlink=getcache('nextlink_' . $path . '_page_' . $page1, $_SERVER['disktag']);
                    if ($nextlink!=$children['@odata.nextLink']) {
                        savecache('nextlink_' . $path . '_page_' . $page1, $children['@odata.nextLink'], $_SERVER['disktag']);
                        $pageinfocache['nextlink_' . $path . '_page_' . $page1] = $children['@odata.nextLink'];
                        $pageinfocache = clearbehindvalue($path,$page1,$maxpage,$pageinfocache);
                        $pageinfochange = 1;
                    }
                    $url = $children['@odata.nextLink'];
                    for ($page2=$page1+1;$page2<=$page;$page2++) {
                        sleep(1);
                        $children = json_decode(curl_request($url, false, ['Authorization' => 'Bearer ' . $_SERVER['access_token']])['body'], true);
                        savecache('files_' . $path . '_page_' . $page2, $children['value'], $_SERVER['disktag']);
                        $nextlink=getcache('nextlink_' . $path . '_page_' . $page2, $_SERVER['disktag']);
                        if ($nextlink!=$children['@odata.nextLink']) {
                            savecache('nextlink_' . $path . '_page_' . $page2, $children['@odata.nextLink'], $_SERVER['disktag']);
                            $pageinfocache['nextlink_' . $path . '_page_' . $page2] = $children['@odata.nextLink'];
                            $pageinfocache = clearbehindvalue($path,$page2,$maxpage,$pageinfocache);
                            $pageinfochange = 1;
                        }
                        $url = $children['@odata.nextLink'];
                    }
                    //echo $url . '<br><pre>' . json_encode($children, JSON_PRETTY_PRINT) . '</pre>';
                    $files['children'] = $children['value'];
                    $files['folder']['page']=$page;
                    $pageinfocache['filenum'] = $files['folder']['childCount'];
                    $pageinfocache['dirsize'] = $files['size'];
                    $pageinfocache['cachesize'] = $cachefile['size'];
                    $pageinfocache['size'] = $files['size']-$cachefile['size'];
                    //if ($pageinfochange == 1) MSAPI('PUT', path_format($path.'/'.$cachefilename), json_encode($pageinfocache, JSON_PRETTY_PRINT), $_SERVER['access_token'])['body'];
                    return $files;
                }
            } else {
                for ($page2=$page3+1;$page2<=$page;$page2++) {
                    sleep(1);
                    $children = json_decode(curl_request($url, false, ['Authorization' => 'Bearer ' . $_SERVER['access_token']])['body'], true);
                    savecache('files_' . $path . '_page_' . $page2, $children['value'], $_SERVER['disktag'], 3300);
                    $nextlink=getcache('nextlink_' . $path . '_page_' . $page2, $_SERVER['disktag']);
                    if ($nextlink!=$children['@odata.nextLink']) {
                        savecache('nextlink_' . $path . '_page_' . $page2, $children['@odata.nextLink'], $_SERVER['disktag'], 3300);
                        $pageinfocache['nextlink_' . $path . '_page_' . $page2] = $children['@odata.nextLink'];
                        $pageinfocache = clearbehindvalue($path,$page2,$maxpage,$pageinfocache);
                        $pageinfochange = 1;
                    }
                    $url = $children['@odata.nextLink'];
                }
                //echo $url . '<br><pre>' . json_encode($children, JSON_PRETTY_PRINT) . '</pre>';
                $files['children'] = $children['value'];
                $files['folder']['page']=$page;
                $pageinfocache['filenum'] = $files['folder']['childCount'];
                $pageinfocache['dirsize'] = $files['size'];
                $pageinfocache['cachesize'] = $cachefile['size'];
                $pageinfocache['size'] = $files['size']-$cachefile['size'];
                //if ($pageinfochange == 1) MSAPI('PUT', path_format($path.'/'.$cachefilename), json_encode($pageinfocache, JSON_PRETTY_PRINT), $_SERVER['access_token'])['body'];
                return $files;
            }
        }
    } else {
        $files['folder']['page']=$page;
        for ($page4=1;$page4<=$maxpage;$page4++) {
            if (!($url = getcache('nextlink_' . $path . '_page_' . $page4, $_SERVER['disktag']))) {
                if ($files['folder'][$path.'_'.$page4]!='') savecache('nextlink_' . $path . '_page_' . $page4, $files['folder'][$path.'_'.$page4], $_SERVER['disktag']);
            } else {
                $files['folder'][$path.'_'.$page4] = $url;
            }
        }
    }
    return $files;
}

function AddDisk()
{
    global $constStr;
    global $CommonEnv;

    $_SERVER['disktag'] = $_COOKIE['disktag'];
    config_oauth();
    $envs = '';
    foreach ($CommonEnv as $env) $envs .= '\'' . $env . '\', ';
    $url = path_format($_SERVER['PHP_SELF'] . '/');

    if (isset($_GET['install2']) && isset($_GET['code'])) {
        $timestamp = time();
        $appSignature = hash_hmac('sha1', 'appKey=' . $_SERVER['appKey'] . '&timestamp=' . $timestamp, $_SERVER['appSecret']);
        $tmpurl = $_SERVER['oauth_url'] . 'accessToken.action?appKey=' . $_SERVER['appKey'] . '&appSignature=' . $appSignature . '&grantType=authorization_code&timestamp=' . $timestamp . '&code=' . $_GET['code'];
        $tmp = curl('GET', $tmpurl, '', [ "User-Agent" => "Mozilla\/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/85.0.4183.121 Safari\/537.36" ], 1);
        //if (isset($tmp['returnhead']['Set-Cookie'])) {
        //    $tmp = curl('GET', $tmpurl, '', [ 'Cookie' => $tmp['returnhead']['Set-Cookie'] ], 1);
        //}
        if ($tmp['stat']==200) $ret = json_decode($tmp['body'], true);
        if (isset($ret['refreshToken'])) {
            $refresh_token = $ret['refreshToken'];
            $str = '
        refresh_token :<br>';
            $str .= '
        <textarea readonly style="width: 95%">' . $refresh_token . '</textarea><br><br>
        ' . getconstStr('SavingToken') . '
        <script>
            var texta=document.getElementsByTagName(\'textarea\');
            for(i=0;i<texta.length;i++) {
                texta[i].style.height = texta[i].scrollHeight + \'px\';
            }
        </script>';
            $tmptoken['refresh_token'] = $refresh_token;
            $tmptoken['access_token'] = $ret['accessToken'];
            $tmptoken['code'] = $_GET['code'];
            $tmptoken['token_expires'] = time()+7*24*60*60;
            //$tmp1 = CTAPI($tmptoken['access_token'], $_SERVER['appSecret'], 'GET', 'getFolderInfo')['body'];
            $tmp1 = json_decode(CTAPI($_SERVER['access_token'], $_SERVER['appSecret'], 'GET', 'getFolderInfo')['body'], true);
            $tmptoken['public_path'] = $tmp1['folderInfo']['path'];
            $response = setConfigResponse( setConfig($tmptoken, $_COOKIE['disktag']) );
            if (api_error($response)) {
                $html = api_error_msg($response);
                $title = 'Error';
                return message($html, $title, 201);
            } else {
                savecache('access_token', $ret['accessToken'], $_COOKIE['disktag'], $ret['expires_in'] - 60);
                $str .= '
                <meta http-equiv="refresh" content="5;URL=' . $url . '">
                <script>document.cookie=\'disktag=; path=/\';</script>';
                return message($str, getconstStr('WaitJumpIndex'), 201);
            }
        }
        return message('<pre>' . $tmpurl . PHP_EOL . 'body:' . $tmp['body'] . PHP_EOL . 'head:' . json_encode($tmp['returnhead'], JSON_PRETTY_PRINT) . '</pre>', $tmp['stat']);
        //return message('<pre>' . json_encode($ret, JSON_PRETTY_PRINT) . '</pre>', 500);
    }

    if (isset($_GET['install1'])) {
        $timestamp = time();
        $appSignature = hash_hmac('sha1', 'appKey=' . $_SERVER['appKey'] . '&timestamp=' . $timestamp, $_SERVER['appSecret']);
        //url="' . $_SERVER['oauth_url'] . '?appKey=' . $_SERVER['appKey'] . '&appSignature=' . $appSignature . '&callbackUrl=' . $_SERVER['callbackUrl'] . '&responseType=code&display=&timestamp=' . $timestamp . '&state=' . '"+encodeURIComponent(url);
            return message('
    <a href="" id="a1">' . getconstStr('JumptoOffice') . '</a>
    <script>
        url=location.protocol + "//" + location.host + "' . $url . '";
        url="' . $_SERVER['oauth_url'] . 'authorize.action?appKey=' . $_SERVER['appKey'] . '&appSignature=' . $appSignature . '&callbackUrl=' . $_SERVER['callbackUrl'] . '&responseType=code&display=&timestamp=' . $timestamp . '&state=' . '"+encodeURIComponent(url);
        document.getElementById(\'a1\').href=url;
        //window.open(url,"_blank");
        location.href = url;
    </script>
    ', getconstStr('Wait') . ' 1s', 201);
    }

    if (isset($_GET['install0'])) {
        if ($_POST['disktag_add']!='') {
            if (in_array($_POST['disktag_add'], $CommonEnv)) {
                return message('Do not input ' . $envs . '<br><button onclick="location.href = location.href;">'.getconstStr('Refresh').'</button><script>document.cookie=\'disktag=; path=/\';</script>', 'Error', 201);
            }
            $_SERVER['disktag'] = $_POST['disktag_add'];
            $tmp['disktag_add'] = $_POST['disktag_add'];
            $tmp['diskname'] = $_POST['diskname'];
            $tmp['Driver'] = 'CT';
            $response = setConfigResponse( setConfig($tmp, $_COOKIE['disktag']) );
            if (api_error($response)) {
                $html = api_error_msg($response);
                $title = 'Error';
            } else {
                $title = getconstStr('MayinEnv');
                $html = getconstStr('Wait') . ' 3s<meta http-equiv="refresh" content="3;URL=' . $url . '?AddDisk&Driver=CT&install1">';
            }
            return message($html, $title, 201);
        }
    }

    $html = '
<div>
    <form action="?AddDisk&Driver=CT&install0" method="post" onsubmit="return notnull(this);">
        ' . getconstStr('DiskTag') . ': (' . getConfig('disktag') . ')
        <input type="text" name="disktag_add" placeholder="' . getconstStr('EnvironmentsDescription')['disktag'] . '" style="width:100%"><br>
        ' . getconstStr('DiskName') . ':
        <input type="text" name="diskname" placeholder="' . getconstStr('EnvironmentsDescription')['diskname'] . '" style="width:100%"><br>
        <br>
        <input type="submit" value="' . getconstStr('Submit') . '">
    </form>
</div>
    <script>
        function notnull(t)
        {
            if (t.disktag_add.value==\'\') {
                alert(\'' . getconstStr('OnedriveDiskTag') . '\');
                return false;
            }
            envs = [' . $envs . '];
            if (envs.indexOf(t.disktag_add.value)>-1) {
                alert("Do not input ' . $envs . '");
                return false;
            }
            var reg = /^[a-zA-Z]([-_a-zA-Z0-9]{1,20})$/;
            if (!reg.test(t.disktag_add.value)) {
                alert(\'' . getconstStr('TagFormatAlert') . '\');
                return false;
            }
            var expd = new Date();
            expd.setTime(expd.getTime()+(2*60*60*1000));
            var expires = "expires="+expd.toGMTString();
            document.cookie=\'disktag=\'+t.disktag_add.value+\'; path=/; \'+expires;
            return true;
        }
    </script>';
    $title = 'Input a Tag';
    return message($html, $title, 201);
}
