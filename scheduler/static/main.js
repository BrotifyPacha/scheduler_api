function dateToStr(date){
    year = date.getFullYear().toString();
    month = (date.getMonth()+1).toString(); // +1 нужен т.к. в js месяц начинается с нуля
    day = date.getDate().toString();

    year = year.substring(2,4);
    if (month.length < 2) month = '0'+month;
    if (day.length < 2) day = '0'+day;
    //console.log(`dateToStr: ${day}.${month}.${year}`)
    return `${day}.${month}.${year}`
}

function strToDate(date_str){
    digits = date_str.split('.')
    year = parseInt(digits[2])+2000;
    month = parseInt(digits[1]);
    day = parseInt(digits[0]);
    return new Date(year, month, day)
}

function millisToDate(millis){
    return new Date(millis)
}

function dateToMillis(date){
    return new Date(date.getFullYear(), date.getMonth(), date.getDate()).getTime()
}
