/**
 * 
 */

const apiUrl = 'https://localhost:4567';

function createSpace(name, owner) {
	let data = {name: name, owner:owner};
	//let csrfToken = getCookie('csrfToken');
	let csrfToken = localStorage.getItem('token');
	console.log('Token value = ',csrfToken);
	
	fetch(apiUrl + '/spaces', {
		method: 'POST',
		//credentials: 'include',
		body: JSON.stringify(data),
		headers: {
			'Content-Type': 'application/json',
			'Authorization':'Bearer '+csrfToken
			//'X-CSRF-Token': csrfToken
		}
	})
	.then(response => {
		if (response.ok) {
			return response.json();
		} else if (response.status === 401) {
			window.location.replace('/login.html');		
		} else {
			throw Error(response.statusText);
		}
	})
	.then(json => console.log('Created space: ',json.name, json.uri))
	.catch(error => console.error('Error: ',error));
}

function logout() {
	let data = {};
	//let csrfToken = getCookie('csrfToken');
	let csrfToken = localStorage.getItem('token');

	
	fetch(apiUrl + '/sessions', {
		method: 'DELETE',
		body: JSON.stringify(data),
		headers: {
			'Content-Type': 'application/json',
			'Authorization':'',
			'X-CSRF-Token': csrfToken
		}
	})
	.then(response => {
		if (response.ok) {
			return response.json();
		} else if (response.status === 401) {
			window.location.replace('/login.html');		
		} else {
			throw Error(response.statusText);
		}
	})
	.then(json => console.log('Successfully logged out of session: '))
	.catch(error => console.error('Error: ',error));
}

window.addEventListener('load', function(e) {
	document.getElementById('createSpace').addEventListener('submit',processFormSubmit);
});


window.addEventListener('load', function(e) {
	document.getElementById('logout').addEventListener('submit',processLogoutSubmit);
});

function processFormSubmit(e) {
	e.preventDefault();
	let spaceName = document.getElementById('spaceName').value;
	let owner = document.getElementById('owner').value;
	
	createSpace(spaceName,owner);
	
	return false;
}

function processLogoutSubmit(e) {
	e.preventDefault();
	
	logout();
	
	return false;
}
function getCookie(cookieName) {
	var cookieValue = document.cookie.split(';').map(item => item.split('=').map(x => decodeURIComponent(x.trim()))).filter(item => item[0] === cookieName)[0];
	console.log('Cookie value = ',cookieValue);
	
	if(cookieValue) {
		return cookieValue[1];
	}
}