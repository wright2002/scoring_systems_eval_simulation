import csv

with open("C:\\Users\Kyle Wright\Desktop\Test_Results\\2024_04_19_vuln_test\TestResults.2024.Apr.19.02_54_02.csv", newline='', encoding='utf-8-sig') as csvfile:
    csvReader = csv.reader(csvfile, delimiter=' ', quotechar='|')
    outputList = []
    marist_exposure = 0
    CVSS_exposure = 0
    EPSS_exposure = 0
    FIFO_exposure = 0
    LIFO_exposure = 0
    Random_exposure = 0

    headers = next(csvReader)

    for row in csvReader:
        rowStr = row[0]
        nextDelimiter = rowStr.find(",")
        outputIndex = [rowStr[0:nextDelimiter]]
        rowStr = rowStr[nextDelimiter + 1:]
        nextDelimiter = rowStr.find(",")
        marist_exposure += float(rowStr[0:nextDelimiter])
        rowStr = rowStr[nextDelimiter + 1:]
        nextDelimiter = rowStr.find(",")
        CVSS_exposure += float(rowStr[0:nextDelimiter])
        rowStr = rowStr[nextDelimiter + 1:]
        nextDelimiter = rowStr.find(",")
        EPSS_exposure += float(rowStr[0:nextDelimiter])
        rowStr = rowStr[nextDelimiter + 1:]
        nextDelimiter = rowStr.find(",")
        FIFO_exposure += float(rowStr[0:nextDelimiter])
        rowStr = rowStr[nextDelimiter + 1:]
        nextDelimiter = rowStr.find(",")
        LIFO_exposure += float(rowStr[0:nextDelimiter])
        rowStr = rowStr[nextDelimiter + 1:]
        Random_exposure += float(rowStr)
        outputIndex.append(marist_exposure)
        outputIndex.append(CVSS_exposure)
        outputIndex.append(EPSS_exposure)
        outputIndex.append(FIFO_exposure)
        outputIndex.append(LIFO_exposure)
        outputIndex.append(Random_exposure)

        print(outputIndex)
        outputList.append(outputIndex)


with open('2024_04_19_vuln_test_exposure.csv', 'w', newline='') as csvfile:
    csvWriter = csv.writer(csvfile)
    csvWriter.writerow(headers)
    csvWriter.writerows(outputList)
