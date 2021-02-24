var dataConstellations =
    {
    "constellation": {
        "abbreviation": "UMa",
        "alias": "the greater bear",
        "declination": "50°",
        "id": 82,
        "max_latitude": 90,
        "min_latitude": -30,
        "name": "ursa major",
        "quadrant": "NQ2",
        "right_ascension": "11h",
        "stars": [
            {
                "apparent_magnitude": 1.76,
                "name": "alioth"
            },
            {
                "apparent_magnitude": 1.81,
                "name": "dubhe"
            },
            {
                "apparent_magnitude": 1.85,
                "name": "alkaid"
            },
            {
                "apparent_magnitude": 2.23,
                "name": "mizar"
            },
            {
                "apparent_magnitude": 2.34,
                "name": "merak"
            },
            {
                "apparent_magnitude": 2.41,
                "name": "phecda"
            },
            {
                "apparent_magnitude": 3.32,
                "name": "megrez"
            }
        ]
    }
};

var dataStars = {
    "star": {
        "apparent_magnitude": 1.97,
        "constellation": {
            "abbreviation": "UMi",
            "name": "ursa minor"
        },
        "declination": "+89° 15′ 50.9″",
        "distance": 431.0,
        "name": "polaris",
        "right_ascension": "02h 31m 47.08s",
        "type": "F7 Ib-IIv"
    }
};

var dataWhere = {
    "declination": "+89° 15′ 50.9″",
    "lat": "-10",
    "lon": "80",
    "star": "polaris",
    "where": "polaris is not visible from your location"
};

var dataWhere2 = {
    "current delay": "-20h 31m 47.08s",
    "declination": "+89° 15′ 50.9″",
    "it rises": "polaris is circumpolar star, hence it is always visible from this location",
    "lat": "51° 30' 26.35884'' N",
    "lon": "0° 7' 39.53064'' E",
    "star": "polaris",
    "sunrise at location": 7.14,
    "sunset at location": 17.13,
    "where": "38° towards north"
};

var dataWhere3 = {
    "current delay": "-20h 7m 10.4s",
    "current position": "It has already set",
    "declination": "+23° 27′ 45″",
    "it rises": 11,
    "it sets": 23,
    "lat": "51° 30' 26.35884'' N",
    "lon": "0° 7' 39.53064'' E",
    "star": "hamal",
    "sunrise at location": 7.12,
    "sunset at location": 17.15,
    "where": "28° towards south"
};

var jsonDiv = JSON.stringify(dataConstellations, undefined, 4);
var jsonStars = JSON.stringify(dataStars, undefined, 4);
var jsonWhere = JSON.stringify(dataWhere, undefined, 4);
var jsonWhere2 = JSON.stringify(dataWhere2, undefined, 4);
var jsonWhere3 = JSON.stringify(dataWhere3, undefined, 4);

var match = document.getElementById("json");
var matchStars = document.getElementById("star-json");
var matchWhere = document.getElementById("where-json-1");
var matchWhere2 = document.getElementById("where-json-2");
var matchWhere3 = document.getElementById("where-json-3");

match.innerHTML = jsonDiv;
matchStars.innerHTML = jsonStars;
matchWhere.innerHTML = jsonWhere;
matchWhere2.innerHTML = jsonWhere2;
matchWhere3.innerHTML = jsonWhere3;

function reveal(){
    var answer = document.getElementById('speed-light-answer');
    if (answer.style.display === "none") {
        answer.style.display = "block";
    } else {
        answer.style.display = "none";
    }
}

function closeMessage() {
    var message = document.querySelector(".message");
    message.style.display = "none";
}
