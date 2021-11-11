$.ajaxSetup({
    contentType: 'application/json',
    // 允許請求帶有驗證訊息
    xhrFields: {withCredentials: true},
    error: function (jqXHR) {
        // 401 未認證，轉至 CAS，service 必須是後端 spring security 的 CAS login URL，renew 不太懂是什麼意思
        if (jqXHR.status === 401) {
            window.location.replace(encodeURI('https://cas.example.org:8443/cas/login?service=http://localhost:8300/back/login/cas&renew=false'));
        }
    }
});

function getUserDetails() {
    $.ajax({
        url: 'http://localhost:8300/back/test/userDetails',
        type: 'post',
        cache: false,
        success: function (data) {
            console.info(data);
            $('#responseBody').text('username: ' + data.username);
        }
    });
}